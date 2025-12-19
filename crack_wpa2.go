package main

import (
    "crypto/hmac"
    "crypto/sha1"
    "encoding/binary"
    "encoding/hex"
    "flag"
    "fmt"
    "io/ioutil"
    "os"
    "os/signal"
    "strings"
    "sync/atomic"
    "time"
    "unicode/utf16"
)

func die(format string, a ...interface{}) {
    fmt.Fprintf(os.Stderr, format+"\n", a...)
    os.Exit(1)
}

func decodeMaybeUTF16(b []byte) string {
    if len(b) >= 2 {
        if b[0] == 0xff && b[1] == 0xfe {
            b = b[2:]
            if len(b)%2 != 0 { b = append(b, 0) }
            u16 := make([]uint16, 0, len(b)/2)
            for i := 0; i < len(b); i += 2 {
                u16 = append(u16, uint16(b[i])|uint16(b[i+1])<<8)
            }
            r := utf16.Decode(u16)
            return string(r)
        } else if b[0] == 0xfe && b[1] == 0xff {
            b = b[2:]
            if len(b)%2 != 0 { b = append(b, 0) }
            u16 := make([]uint16, 0, len(b)/2)
            for i := 0; i < len(b); i += 2 {
                u16 = append(u16, uint16(b[i])<<8|uint16(b[i+1]))
            }
            r := utf16.Decode(u16)
            return string(r)
        }
    }
    return string(b)
}

func parseAlphabetsFromMask(mask string) [][]rune {
    var alnumLower = []rune("abcdefghijklmnopqrstuvwxyz")
    var alnumUpper = []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    var digits = []rune("0123456789")

    res := make([][]rune, 0, len(mask))
    for _, ch := range mask {
        switch ch {
        case 'a':
            merged := make([]rune, 0, len(alnumLower)+len(alnumUpper)+len(digits))
            merged = append(merged, alnumLower...)
            merged = append(merged, alnumUpper...)
            merged = append(merged, digits...)
            res = append(res, merged)
        case 'd':
            res = append(res, digits)
        case 'l':
            res = append(res, alnumLower)
        case 'u':
            res = append(res, alnumUpper)
        default:
            die("Unknown mask character: %c", ch)
        }
    }
    return res
}

func productCounts(alphabets [][]rune) uint64 {
    var total uint64 = 1
    for _, a := range alphabets {
        total *= uint64(len(a))
    }
    return total
}

func hmacSha1(key, data []byte) []byte {
    mac := hmac.New(sha1.New, key)
    mac.Write(data)
    return mac.Sum(nil)
}

func pbkdf2Sha1(password, salt []byte, iter, dklen int) []byte {
    hLen := 20
    l := (dklen + hLen - 1) / hLen
    var dk []byte
    for i := 1; i <= l; i++ {
        intBytes := make([]byte, 4)
        binary.BigEndian.PutUint32(intBytes, uint32(i))
        U := hmacSha1(password, append(salt, intBytes...))
        T := make([]byte, len(U))
        copy(T, U)
        for j := 1; j < iter; j++ {
            U = hmacSha1(password, U)
            for k := 0; k < len(T); k++ {
                T[k] ^= U[k]
            }
        }
        dk = append(dk, T...)
    }
    return dk[:dklen]
}

func prf512(pmk []byte, A, B []byte) []byte {
    out := make([]byte, 0, 64)
    var counter byte = 1
    for len(out) < 64 {
        mac := hmac.New(sha1.New, pmk)
        mac.Write(A)
        mac.Write([]byte{0x00})
        mac.Write(B)
        mac.Write([]byte{counter})
        out = append(out, mac.Sum(nil)...)
        counter++
    }
    return out[:64]
}

func buildPassword(alphabets [][]rune, indices []int) string {
    r := make([]rune, len(alphabets))
    for i := range alphabets {
        r[i] = alphabets[i][indices[i]]
    }
    return string(r)
}

func main() {
    mask := flag.String("m", "", "mask, e.g. aaadd (required)")
    flag.Parse()
    if *mask == "" {
        die("Usage: go run crack_wpa2.go -m <mask> <file>")
    }
    if flag.NArg() < 1 {
        die("Provide input file produced by gen_wpa2.py")
    }
    filename := flag.Arg(0)
    data, err := ioutil.ReadFile(filename)
    if err != nil {
        die("Read file: %v", err)
    }
    text := strings.TrimSpace(decodeMaybeUTF16(data))
    parts := strings.Split(text, "*")
    if len(parts) < 7 {
        die("Expected 7 '*' separated fields, got %d", len(parts))
    }
    ssid := parts[0]
    apmac, err := hex.DecodeString(parts[1])
    if err != nil { die("ap mac: %v", err) }
    stamac, err := hex.DecodeString(parts[2])
    if err != nil { die("sta mac: %v", err) }
    anonce, err := hex.DecodeString(parts[3])
    if err != nil { die("anonce: %v", err) }
    snonce, err := hex.DecodeString(parts[4])
    if err != nil { die("snonce: %v", err) }
    eapol, err := hex.DecodeString(parts[5])
    if err != nil { die("eapol: %v", err) }
    targetMic, err := hex.DecodeString(parts[6])
    if err != nil { die("mic: %v", err) }

    fmt.Printf("Loaded test vector. SSID=%s, target MIC=%s\n", ssid, hex.EncodeToString(targetMic))

    // build B: min(mac)||max(mac)||min(anonce)||max(anonce)
    var macs [][]byte
    if string(apmac) < string(stamac) {
        macs = [][]byte{apmac, stamac}
    } else {
        macs = [][]byte{stamac, apmac}
    }
    var nonces [][]byte
    if string(anonce) < string(snonce) {
        nonces = [][]byte{anonce, snonce}
    } else {
        nonces = [][]byte{snonce, anonce}
    }
    B := append(append(macs[0], macs[1]...), append(nonces[0], nonces[1]...)...)

    alphabets := parseAlphabetsFromMask(*mask)
    total := productCounts(alphabets)
    fmt.Printf("Mask: %s -> positions: %d, total combos: %d\n", *mask, len(alphabets), total)

    indices := make([]int, len(alphabets))
    var attempts uint64 = 0
    var done uint32 = 0
    start := time.Now()

    ticker := time.NewTicker(2 * time.Second)
    defer ticker.Stop()
    interrupt := make(chan os.Signal, 1)
    signal.Notify(interrupt, os.Interrupt)

    go func() {
        for {
            select {
            case <-ticker.C:
                a := atomic.LoadUint64(&attempts)
                el := time.Since(start)
                speed := float64(a) / el.Seconds()
                percent := float64(a) / float64(total) * 100.0
                curr := buildPassword(alphabets, indices)
                fmt.Printf("Tried: %d / %d (%.6f%%), speed: %.0f tries/s, elapsed: %s, current: %s\n",
                    a, total, percent, speed, el.Truncate(time.Second), curr)
            case <-interrupt:
                atomic.StoreUint32(&done, 1)
                return
            }
        }
    }()

    found := false
    var foundPw string

mainloop:
    for {
        pw := []byte(buildPassword(alphabets, indices))
        pmk := pbkdf2Sha1(pw, []byte(ssid), 4096, 32)
        A := []byte("Pairwise key expansion")
        ptk := prf512(pmk, A, B)
        kck := ptk[:16]

        mac := hmac.New(sha1.New, kck)
        mac.Write(eapol)
        full := mac.Sum(nil)
        computed := full[:len(targetMic)]

        atomic.AddUint64(&attempts, 1)

        if hmac.Equal(computed, targetMic) {
            found = true
            foundPw = string(pw)
            break mainloop
        }

        for i := len(indices)-1; i >= 0; i-- {
            indices[i]++
            if indices[i] < len(alphabets[i]) {
                break
            }
            indices[i] = 0
            if i == 0 {
                break mainloop
            }
        }
        if atomic.LoadUint32(&done) == 1 {
            println("\nInterrupted by user")
            break
        }
    }

    elapsed := time.Since(start)
    if found {
        fmt.Printf("\nFOUND password: %s\nAttempts: %d, elapsed: %s, speed: %.0f tries/s\n",
            foundPw, atomic.LoadUint64(&attempts), elapsed.Truncate(time.Second),
            float64(atomic.LoadUint64(&attempts))/elapsed.Seconds())
    } else {
        fmt.Printf("\nPassword NOT found. Attempts: %d, elapsed: %s, speed: %.0f tries/s\n",
            atomic.LoadUint64(&attempts), elapsed.Truncate(time.Second),
            float64(atomic.LoadUint64(&attempts))/elapsed.Seconds())
    }
}
