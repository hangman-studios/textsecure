// Copyright (c) 2014 Canonical Ltd.
// Licensed under the GPLv3, see the COPYING file for details.

package transport

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strconv"
	"regexp"
	"strings"
	"time"

	"github.com/signal-golang/textsecure/helpers"
	"github.com/signal-golang/textsecure/rootCa"
	log "github.com/sirupsen/logrus"
)

var Transport Transporter

func SetupTransporter(server string,
	uuid string,
	password string,
	userAgent string,
	proxyServer string) {
	Transport = newHTTPTransporter(server, uuid, password, userAgent, proxyServer, rootCa.RootCA)
}

var CdnTransport *httpTransporter

func SetupCDNTransporter(cdnUrl string, tel string, password string, userAgent string, proxyServer string) {
	// setupCA()
	CdnTransport = newHTTPTransporter(cdnUrl, tel, password, userAgent, proxyServer, rootCa.RootCA)
}

var DirectoryTransport *httpTransporter

func SetupDirectoryTransporter(Url string, uuid string, password string, userAgent string, proxyServer string) {
	// setupCA()
	DirectoryTransport = newHTTPTransporter(Url, uuid, password, userAgent, proxyServer, rootCa.DirectoryCA)
}

var StorageTransport *httpTransporter

func SetupStorageTransporter(Url string, uuid string, password string, userAgent string, proxyServer string) {
	// setupCA()
	StorageTransport = newHTTPTransporter(Url, uuid, password, userAgent, proxyServer, rootCa.DirectoryCA)
}

var ServiceTransport *httpTransporter

func SetupServiceTransporter(Url string, uuid string, password string, userAgent string, proxyServer string) {
	ServiceTransport = newHTTPTransporter(Url, uuid, password, userAgent, proxyServer, rootCa.DirectoryCA)
}

type response struct {
	Status  int
	Body    io.ReadCloser
	Cookies string
	Header  *http.Header
}

func (r *response) IsError() bool {
	return r.Status < 200 || r.Status >= 300
}

func (r *response) Error() string {
	return fmt.Sprintf("status code %d\n", r.Status)
}

type Transporter interface {
	Get(url string) (*response, error)
	Del(url string) (*response, error)
	Put(url string, body []byte, ct string) (*response, error)
	PostWithHeaders(url string, body []byte, contentType string, headers map[string]string) (*response, error)
	PutWithAuth(url string, body []byte, ct string, auth string) (*response, error)
	PatchWithAuth(url string, body []byte, ct string, auth string) (*response, error)

	PutJSON(url string, body []byte) (*response, error)
	PutBinary(url string, body []byte) (*response, error)
	PutJSONWithAuth(url string, body []byte, auth string) (*response, error)
	PutJSONWithUnidentifiedSender(url string, body []byte, unidentifiedAccessKey []byte) (*response, error)
	GetWithUnidentifiedAccessKey(url string, unidentifiedAccessKey []byte) (*response, error)
}

type httpTransporter struct {
	baseURL     string
	user        string
	pass        string
	proxyServer string
	userAgent   string
	client      *http.Client
}

// func getProxy(req *http.Request) (*url.URL, error) {
// 	if config.ProxyServer != "" {
// 		u, err := url.Parse(config.ProxyServer)
// 		if err == nil {
// 			return u, nil
// 		}
// 	}
// 	return http.ProxyFromEnvironment(req)
// }

func NewHTTPClient() *http.Client {
	client := &http.Client{
		Transport: &http.Transport{
			TLSHandshakeTimeout: 30 * time.Second,
		},
		Timeout: 45 * time.Second,
	}

	return client
}

func newHTTPTransporter(baseURL, user, pass string, userAgent string, proxyServer string, rootCA *x509.CertPool) *httpTransporter {
	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:            rootCA,
				InsecureSkipVerify: true,
			},
			// Proxy:           getProxy,
		},
	}

	return &httpTransporter{baseURL, user, pass, userAgent, proxyServer, client}
}

func (ht *httpTransporter) Get(url string) (*response, error) {
	req, err := http.NewRequest("GET", ht.baseURL+url, nil)
	if err != nil {
		return nil, err
	}
	if ht.userAgent != "" {
		req.Header.Set("X-Signal-Agent", ht.userAgent)
	}
	req.SetBasicAuth(ht.user, ht.pass)
	resp, err := ht.client.Do(req)
	PrintBodyAndHeader(resp, err, "Get", url)
	if err != nil {
		return nil, err
	}
	r := &response{}
	if resp != nil {
		r.Status = resp.StatusCode
		r.Body = resp.Body
	}

	log.Debugf("[textsecure] GET %s %d\n", url, r.Status)

	return r, err
}
func (ht *httpTransporter) GetWithAuth(url string, auth string) (*response, error) {
	req, err := http.NewRequest("GET", ht.baseURL+url, nil)
	if err != nil {
		return nil, err
	}
	if ht.userAgent != "" {
		req.Header.Set("X-Signal-Agent", ht.userAgent)
	}
	req.Header.Set("Authorization", auth)
	resp, err := ht.client.Do(req)
	PrintBodyAndHeader(resp, err, "GetWithAuth", url)
	if err != nil {
		return nil, err
	}
	r := &response{}
	if resp != nil {
		r.Status = resp.StatusCode
		r.Body = resp.Body
	}

	log.Debugf("[textsecure] GET with auth %s %d\n", url, r.Status)

	return r, err
}
func (ht *httpTransporter) Del(url string) (*response, error) {
	req, err := http.NewRequest("DELETE", ht.baseURL+url, nil)
	if err != nil {
		return nil, err
	}
	if ht.userAgent != "" {
		req.Header.Set("X-Signal-Agent", ht.userAgent)
	}
	req.SetBasicAuth(ht.user, ht.pass)
	resp, err := ht.client.Do(req)
	PrintBodyAndHeader(resp, err, "Del", url)
	if err != nil {
		return nil, err
	}
	r := &response{}
	if resp != nil {
		r.Status = resp.StatusCode
		r.Body = resp.Body
	}

	log.Debugf("DELETE %s %d\n", url, r.Status)

	return r, err
}

func (ht *httpTransporter) PostWithHeaders(url string, body []byte, ct string, headers map[string]string) (*response, error) {
	br := bytes.NewReader(body)
	req, err := http.NewRequest("POST", ht.baseURL+url, br)
	if err != nil {
		return nil, err
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	if ht.userAgent != "" {
		req.Header.Set("X-Signal-Agent", ht.userAgent)
	}
	req.Header.Add("Content-Type", ct)
	req.Header.Add("Content-Length", strconv.Itoa(len(body)))
	req.SetBasicAuth(ht.user, ht.pass)
	resp, err := ht.client.Do(req)
	if err != nil {
		return nil, err
	}
	r := &response{}
	if resp != nil {
		r.Status = resp.StatusCode
		r.Body = resp.Body
		r.Header = &resp.Header
	}

	log.Debugf("[textsecure] POST %s %d\n", url, r.Status)

	return r, err
}

var endpointCalls map[string][]time.Time

func PrintBodyAndHeader(resp *http.Response, err error, functionName string, endpoint string) {
	if endpointCalls == nil {
		endpointCalls = make(map[string][]time.Time, 6)
	}
	if resp == nil {
		log.Debugf("[textsecure] PrintBodyAndHeader resp is nil, err is: %s, function: %s", err, functionName)
		return
	}
	bodyBytes, readerr := ioutil.ReadAll(resp.Body)
	if readerr != nil {
		log.Debugf("[textsecure] %s while reading body %s\n", functionName, readerr)
	}
	closeErr := resp.Body.Close() //  must close
	if closeErr != nil {
		log.Debugf("[textsecure] %s while closing body %s\n", functionName, closeErr)
	}
	resp.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))
	tokens := strings.Split(endpoint, "/")
	filteredTokens := make([]string, 0, 4)
	var hasLetters = regexp.MustCompile(`[a-zA-Z]+`).MatchString
	var hasNumbers = regexp.MustCompile(`[0-9]+`).MatchString
	for _, token := range tokens {
		onlyLetters := true
		if hasLetters(token) && hasNumbers(token) || hasNumbers(token) {
			onlyLetters = false
		}
		if onlyLetters {
			filteredTokens = append(filteredTokens, token)
		} else {
			filteredTokens = append(filteredTokens, "...")
		}
	}
	filteredEndpoint := strings.Join(filteredTokens, "/")
	tmp := make([]time.Time, 0, len(endpointCalls[filteredEndpoint]))
	for _, timestamp := range endpointCalls[filteredEndpoint] {
		if time.Now().Sub(timestamp) < time.Second*60 {
			tmp = append(tmp, timestamp)
		}
	}
	tmp = append(tmp, time.Now())
	endpointCalls[filteredEndpoint] = tmp
	log.Debugf("[textsecure] %s response: %+v", functionName, resp)
	log.Debugf("Called: %s, calls/min: %d", filteredEndpoint, len(endpointCalls[filteredEndpoint]))
	log.Debugf("Error: %+v", err)
	log.Debugf("Headers:")
	for key, value := range resp.Header {
		log.Debugf("  \"%s\" = \"%s\"", key, value)
	}
	log.Debugf("Body: %+v", resp.Body)
	log.Debugf("Body read: %s", bodyBytes)

}

func (ht *httpTransporter) Put(url string, body []byte, ct string) (*response, error) {
	br := bytes.NewReader(body)
	req, err := http.NewRequest("PUT", ht.baseURL+url, br)
	if err != nil {
		return nil, err
	}
	if ht.userAgent != "" {
		req.Header.Set("X-Signal-Agent", ht.userAgent)
	}
	req.Header.Add("Content-Type", ct)
	req.SetBasicAuth(ht.user, ht.pass)
	resp, err := ht.client.Do(req)
	PrintBodyAndHeader(resp, err, "PUT", url)
	if err != nil {
		return nil, err
	}
	r := &response{}
	if resp != nil {
		r.Status = resp.StatusCode
		r.Body = resp.Body
	}

	log.Debugf("[textsecure] PUT %s %d\n", url, r.Status)

	return r, err
}
func (ht *httpTransporter) PutWithAuth(url string, body []byte, ct string, auth string) (*response, error) {
	br := bytes.NewReader(body)
	req, err := http.NewRequest("PUT", ht.baseURL+url, br)
	if err != nil {
		return nil, err
	}
	if ht.userAgent != "" {
		req.Header.Set("X-Signal-Agent", ht.userAgent)
	}
	req.Header.Get("Authorization")
	req.Header.Add("Content-Type", ct)
	req.Header.Set("Authorization", auth)
	resp, err := ht.client.Do(req)
	PrintBodyAndHeader(resp, err, "PutWithAuth", url)
	if err != nil {
		return nil, err
	}
	cookies := resp.Header.Get("Set-Cookie")
	r := &response{}
	if resp != nil {
		r.Status = resp.StatusCode
		r.Body = resp.Body
		r.Cookies = cookies
	}

	log.Debugf("[textsecure] PUT with auth %s %d\n", url, r.Status)

	return r, err
}
func (ht *httpTransporter) GetWithUnidentifiedAccessKey(url string, unidentifedAccessKey []byte) (*response, error) {
	req, err := http.NewRequest("GET", ht.baseURL+url, nil)
	if err != nil {
		return nil, err
	}
	if ht.userAgent != "" {
		req.Header.Set("X-Signal-Agent", ht.userAgent)
	}
	req.Header.Set("Unidentified-Access-Key", base64.StdEncoding.EncodeToString(unidentifedAccessKey))
	resp, err := ht.client.Do(req)
	if err != nil {
		return nil, err
	}
	r := &response{}
	if resp != nil {
		r.Status = resp.StatusCode
		r.Body = resp.Body
	}

	log.Debugf("[textsecure] GET with unidentified access key %s %d\n", url, r.Status)

	return r, err
}
func (ht *httpTransporter) PutWithUnidentifiedSender(url string, body []byte, ct string, unidentifiedAccessKey []byte) (*response, error) {
	br := bytes.NewReader(body)
	req, err := http.NewRequest("PUT", ht.baseURL+url, br)
	if err != nil {
		return nil, err
	}
	if ht.userAgent != "" {
		req.Header.Set("X-Signal-Agent", ht.userAgent)
	}
	req.Header.Get("Authorization")
	req.Header.Add("Content-Type", ct)
	unidentifiedAccessKeyBase64 := helpers.Base64EncWithoutPadding(unidentifiedAccessKey)
	req.Header.Set("Unidentified-Access-Key", unidentifiedAccessKeyBase64)
	resp, err := ht.client.Do(req)
	PrintBodyAndHeader(resp, err, "PutWithUnidentifiedSender", url)
	if err != nil {
		return nil, err
	}
	cookies := resp.Header.Get("Set-Cookie")
	r := &response{}
	if resp != nil {
		r.Status = resp.StatusCode
		r.Body = resp.Body
		r.Cookies = cookies
	}

	log.Debugf("[textsecure] PUT with unidentified sender %s %d\n", url, r.Status)

	return r, err
}
func (ht *httpTransporter) PutWithAuthCookies(url string, body []byte, ct string, auth string, cookies string) (*response, error) {
	br := bytes.NewReader(body)
	req, err := http.NewRequest("PUT", ht.baseURL+url, br)
	if err != nil {
		return nil, err
	}
	if ht.userAgent != "" {
		req.Header.Set("X-Signal-Agent", ht.userAgent)
	}

	req.Header.Add("Cookie", cookies)
	req.Header.Get("Authorization")
	req.Header.Add("Content-Type", ct)
	req.Header.Set("Authorization", auth)

	resp, err := ht.client.Do(req)
	PrintBodyAndHeader(resp, err, "PutWithAuthCookies", url)
	if err != nil {
		return nil, err
	}
	r := &response{}
	if resp != nil {
		r.Status = resp.StatusCode
		r.Body = resp.Body
	}

	log.Debugf("[textsecure] PUT with auth & cookie %s %d \n", url, r.Status)

	return r, err
}
func (ht *httpTransporter) PutJSON(url string, body []byte) (*response, error) {
	return ht.Put(url, body, "application/json")
}
func (ht *httpTransporter) PutJSONWithAuth(url string, body []byte, auth string) (*response, error) {
	return ht.PutWithAuth(url, body, "application/json; charset=utf-8", auth)
}
func (ht *httpTransporter) PutJSONWithAuthCookies(url string, body []byte, auth string, cookies string) (*response, error) {
	return ht.PutWithAuthCookies(url, body, "application/json; charset=utf-8", auth, cookies)
}
func (ht *httpTransporter) PutJSONWithUnidentifiedSender(url string, body []byte, unidentifiedAccessKey []byte) (*response, error) {
	return ht.PutWithUnidentifiedSender(url, body, "application/json; charset=utf-8", unidentifiedAccessKey)
}
func (ht *httpTransporter) PutBinary(url string, body []byte) (*response, error) {
	return ht.Put(url, body, "application/octet-stream")
}
func (ht *httpTransporter) PatchWithAuth(url string, body []byte, ct string, auth string) (*response, error) {
	br := bytes.NewReader(body)
	req, err := http.NewRequest("PATCH", ht.baseURL+url, br)
	if err != nil {
		return nil, err
	}
	if ht.userAgent != "" {
		req.Header.Set("X-Signal-Agent", ht.userAgent)
	}
	req.Header.Get("Authorization")
	req.Header.Add("Content-Type", ct)
	req.Header.Set("Authorization", auth)
	resp, err := ht.client.Do(req)
	PrintBodyAndHeader(resp, err, "PatchWithAuth", url)
	respbody := make([]byte, resp.ContentLength)
	if _, readerr := resp.Body.Read(respbody); readerr != nil {
		fmt.Printf("while reading body: %s", readerr)
	}
	fmt.Printf("Patch response: %+v\nError: %+v\nBody: %+vBody read: %s\n", resp, err, resp.Body, respbody)
	if err != nil {
		return nil, err
	}

	r := &response{}
	if resp != nil {
		r.Status = resp.StatusCode
		r.Body = resp.Body
	}

	log.Debugf("[textsecure] PATCH with auth %s %d\n", url, r.Status)

	return r, err
}

func (ht *httpTransporter) Duplicate() *httpTransporter {
	pHt := *ht
	newTransport := &pHt
	return newTransport
}
