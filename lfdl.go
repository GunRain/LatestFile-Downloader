package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

var (
	LatestFileDownloader_Transport = &LatestFileDownloader_DNSResolverTransport{
		DNSServers: []string{"119.29.29.29:53"},
		Transport:  &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10}},
		preferIPv4: false,
	}
	LatestFileDownloader_Client = &http.Client{
		Transport: LatestFileDownloader_Transport,
		Timeout:   0,
	}
	LatestFileDownloader_UserAgent = `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36`
	LatestFileDownloader_BlockSize = 1 * 1024 * 1024 / 2
	LatestFileDownloader_TryNum    = 5
)

type LatestFileDownloader_DNSResolverTransport struct {
	DNSServers []string
	Transport  http.RoundTripper
	preferIPv4 bool
}

func (d *LatestFileDownloader_DNSResolverTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	parsedURL := req.URL
	host := parsedURL.Hostname()
	port := parsedURL.Port()
	if port == "" {
		if parsedURL.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	ips, err := d.resolveDNS(host)
	if err != nil {
		return nil, err
	}
	var bestIP string
	minDelay := time.Duration(math.MaxInt64)
	for _, ip := range ips {
		start := time.Now()
		_, err := net.DialTimeout("tcp", net.JoinHostPort(ip, port), 2*time.Second)
		if err == nil {
			delay := time.Since(start)
			if delay < minDelay {
				minDelay = delay
				bestIP = ip
			}
		}
	}
	if bestIP != "" {
		req.URL.Host = net.JoinHostPort(bestIP, port)
		req.Host = host
		if tr, ok := d.Transport.(*http.Transport); ok {
			if tr.TLSClientConfig == nil {
				tr.TLSClientConfig = &tls.Config{}
			}
			tr.TLSClientConfig.ServerName = host
		}
	}
	return d.Transport.RoundTrip(req)
}

func (d *LatestFileDownloader_DNSResolverTransport) resolveDNS(host string) ([]string, error) {
	var ips []string
	queryTypes := []uint16{dns.TypeAAAA, dns.TypeA}

	if d.preferIPv4 {
		queryTypes = []uint16{dns.TypeA, dns.TypeAAAA}
	}

	for _, server := range d.DNSServers {
		client := new(dns.Client)
		message := new(dns.Msg)

		for _, qType := range queryTypes {
			message.SetQuestion(dns.Fqdn(host), qType)

			response, _, err := client.Exchange(message, server)
			if err == nil {
				for _, answer := range response.Answer {
					switch aRecord := answer.(type) {
					case *dns.A:
						ips = append(ips, aRecord.A.String())
					case *dns.AAAA:
						ips = append(ips, aRecord.AAAA.String())
					}
				}
			}

			if len(ips) > 0 {
				break
			}
		}

		if len(ips) > 0 {
			break
		}
	}

	if len(ips) == 0 {
		return nil, fmt.Errorf("DNS resolution failed for host: %s", host)
	}

	return ips, nil
}

type LatestFileDownloader struct {
	url           string
	filename      string
	contentLength int64
	acceptRanges  bool
	numThreads    int64
	runThreads    int64
	downloaded    int64
	err           bool
	pause         bool
	resume        bool
	cancel        bool
	ok            bool
	log           string
}

func check(e error, h ...*LatestFileDownloader) bool {
	if e != nil {
		if h != nil {
			h[0].err = true
			h[0].pause = false
			h[0].resume = false
			h[0].cancel = true
			h[0].ok = true
			h[0].log += e.Error()
		}
		return true
	}
	return false
}

func New(link string, numThreads int64, storagePath, customFileName string) *LatestFileDownloader {

	parsedURL, err := url.Parse(link)
	if check(err) {
		return nil
	}
	req, err := http.NewRequest("HEAD", parsedURL.Scheme+"://"+parsedURL.Host+parsedURL.Path, nil)
	if check(err) {
		return nil
	}
	q := parsedURL.Query()
	req.URL.RawQuery = q.Encode()
	req.Header.Set("User-Agent", LatestFileDownloader_UserAgent)
	resp, err := LatestFileDownloader_Client.Do(req)
	if check(err) {
		return nil
	}

	defer resp.Body.Close()

	var filename string
	if parsedURL.Path != "" {
		var urlSplits []string = strings.Split(parsedURL.Path, "/")
		filename = urlSplits[len(urlSplits)-1]
	} else {
		filename = parsedURL.Host
	}

	dl := new(LatestFileDownloader)
	dl.url = link
	dl.contentLength = resp.ContentLength
	dl.numThreads = numThreads
	dl.runThreads = numThreads
	dl.filename = filename
	if customFileName != "" {
		dl.filename = customFileName
	}
	dl.filename = filepath.Join(storagePath, dl.filename)
	dl.err = false
	dl.pause = false
	dl.resume = false
	dl.cancel = false

	dl.acceptRanges = resp.Header.Get("Accept-Ranges") == "bytes"

	dl.ok = false

	return dl
}

func (h *LatestFileDownloader) Download() {
	filePath := h.filename
	f, err := os.Create(filePath)
	if check(err, h) {
		return
	}
	defer f.Close()

	if !h.acceptRanges {
		h.log += "该文件不支持多线程下载，单线程下载中"
		h.numThreads = 1
		h.runThreads = 1
		parsedURL, err := url.Parse(h.url)
		if check(err, h) {
			return
		}
		req, err := http.NewRequest("GET", parsedURL.Scheme+"://"+parsedURL.Host+parsedURL.Path, nil)
		if check(err, h) {
			return
		}
		q := parsedURL.Query()
		req.URL.RawQuery = q.Encode()
		req.Header.Set("User-Agent", LatestFileDownloader_UserAgent)
		resp, err := LatestFileDownloader_Client.Do(req)
		if check(err, h) {
			return
		}
		f, err := os.OpenFile(h.filename, os.O_WRONLY, 0660)
		if check(err, h) {
			return
		}
		start := int64(0)
		f.Seek(start, io.SeekStart)
		buffer := make([]byte, LatestFileDownloader_BlockSize)
		for {
			switch {
			case h.pause:
				for !h.resume {
					time.Sleep(500 * time.Millisecond)
				}
				h.pause = false
			case h.resume:
				h.resume = false
			case h.cancel:
				return
			}
			n, err := resp.Body.Read(buffer)
			if err != nil && err != io.EOF {
				if check(err, h) {
					return
				}
			}
			if n > 0 {
				f.Seek(start, io.SeekStart)
				_, err = f.Write(buffer[:n])
				if err != nil {
					if check(err, h) {
						return
					}
				}
				atomic.AddInt64(&h.downloaded, int64(len(buffer[:n])))
				start += int64(n)
			}
			if err == io.EOF {
				break
			}
		}
		err = resp.Body.Close()
		if check(err, h) {
			return
		}
		h.runThreads = 0
	} else {
		fmt.Println("该文件支持多线程下载，多线程下载中")
		var wg sync.WaitGroup
		for _, ranges := range h.Split() {
			wg.Add(1)
			go func(start, end int64) {
				defer wg.Done()
				h.download(start, end)
			}(ranges[0], ranges[1])
		}
		wg.Wait()
	}
	h.ok = true
}

func (h *LatestFileDownloader) Split() [][]int64 {
	ranges := [][]int64{}
	blockSize := h.contentLength / h.numThreads
	for i := int64(0); i < h.numThreads; i++ {
		var start int64 = i * blockSize
		var end int64 = (i+1)*blockSize - 1
		if i == h.numThreads-1 {
			end = h.contentLength - 1
		}
		ranges = append(ranges, []int64{start, end})
	}
	return ranges
}

func (h *LatestFileDownloader) download(start, end int64) {
	var err error

	var retries int

	f, err := os.OpenFile(h.filename, os.O_WRONLY, 0660)
	if check(err, h) {
		return
	}

	for retries = 0; retries < LatestFileDownloader_TryNum; retries++ {
		parsedURL, err := url.Parse(h.url)
		if check(err, h) {
			return
		}
		req, err := http.NewRequest("GET", parsedURL.Scheme+"://"+parsedURL.Host+parsedURL.Path, nil)
		if check(err, h) {
			return
		}
		q := parsedURL.Query()
		req.URL.RawQuery = q.Encode()
		req.Header.Set("Range", fmt.Sprintf("bytes=%v-%v", start, end))
		req.Header.Set("User-Agent", LatestFileDownloader_UserAgent)

		buffer := make([]byte, LatestFileDownloader_BlockSize)
		resp, err := LatestFileDownloader_Client.Do(req)
		if check(err) {
			goto cannot
		}
		for {
			switch {
			case h.pause:
				for !h.resume {
					time.Sleep(500 * time.Millisecond)
				}
				h.pause = false
			case h.resume:
				h.resume = false
			case h.cancel:
				return
			}

			n, err := resp.Body.Read(buffer)
			if err != nil && err != io.EOF {
				if check(err) {
					goto cannot
				}
			}

			if n > 0 {
				f.Seek(start, io.SeekStart)
				_, err = f.Write(buffer[:n])
				if err != nil {
					if check(err) {
						goto cannot
					}
				}
				atomic.AddInt64(&h.downloaded, int64(len(buffer[:n])))
				start += int64(n)
			}
			if err == io.EOF {
				break
			}
		}
		if (err == nil || err == io.EOF) && resp.StatusCode == http.StatusPartialContent {
			err = resp.Body.Close()
			if check(err) {
				goto cannot
			}
			break
		}

	cannot:
		h.log += fmt.Sprintf("下载分段 %v-%v 失败, 重试次数: %d/%d\n", start, end, retries+1, LatestFileDownloader_TryNum)
		time.Sleep(1 * time.Second)
	}
	if retries == LatestFileDownloader_TryNum {
		h.log += fmt.Sprintf("下载分段 %v-%v 失败，已超过最大重试次数\n", start, end)
		if check(err, h) {
			return
		}
	}
	err = f.Close()
	if check(err, h) {
		return
	}
	h.runThreads--
}
