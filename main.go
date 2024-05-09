package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
)

var (
	CACertFilePath = "/home/ubuntu/ManagementCA.pem"
	CertFilePath   = "/home/ubuntu//certificate.pem"
	KeyFilePath    = "/home/ubuntu//privatekey.pem"
)

type SignatureBody struct {
	Properties Signature `json:"properties"`
}

type Signature struct {
	Description                       string `json:"description"`
	Name                              string `json:"name"`
	Location                          string `json:"LOCATION"`
	DefaultKey                        string `json:"DEFAULTKEY"`
	CryptoToken                       string `json:"CRYPTOTOKEN"`
	Type                              string `json:"TYPE"`
	AddVisibleSignature               string `json:"ADD_VISIBLE_SIGNATURE"`
	Digestalgorithm                   string `json:"DIGESTALGORITHM"`
	ImplementationClass               string `json:"IMPLEMENTATION_CLASS"`
	AuthType                          string `json:"AUTHTYPE"`
	DisableKeyUsageCounter            string `json:"DISABLEKEYUSAGECOUNTER"`
	AllowPropertyOverride             string `json:"ALLOW_PROPERTY_OVERRIDE"`
	VisibleSignatureCustomImageBase64 string `json:"VISIBLE_SIGNATURE_CUSTOM_IMAGE_BASE64"`
	Reason                            string `json:"REASON"`
}

func httpsClient(url string, bodyData SignatureBody) *string {
	// load tls certificates
	clientTLSCert, err := tls.LoadX509KeyPair(CertFilePath, KeyFilePath)
	if err != nil {
		log.Fatalf("Error loading certificate and key file: %v", err)
		return nil
	}
	// Configure the client to trust TLS server certs issued by a CA.
	certPool, err := x509.SystemCertPool()
	if err != nil {
		panic(err)
	}
	if caCertPEM, err := os.ReadFile(CACertFilePath); err != nil {
		panic(err)
	} else if ok := certPool.AppendCertsFromPEM(caCertPEM); !ok {
		panic("invalid cert in CA PEM")
	}
	tlsConfig := &tls.Config{
		RootCAs:            certPool,
		Certificates:       []tls.Certificate{clientTLSCert},
		InsecureSkipVerify: true,
	}
	tr := &http.Transport{
		TLSClientConfig: tlsConfig,
	}
	client := &http.Client{Transport: tr}

	reqBodyBytes := new(bytes.Buffer)
	json.NewEncoder(reqBodyBytes).Encode(bodyData)

	reqBodyBytes.Bytes()
	// var jsonStr, _ = json.Marshal(bodyData)
	// params := bytes.NewBuffer(jsonStr)

	req, _ := http.NewRequest("POST", url, reqBodyBytes)
	req.Header = http.Header{"Content-Type": {"application/json"},
		"X-Keyfactor-Requested-With": {"XMLHttpRequest"}}
	resp, err := client.Do(req)

	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	json.NewDecoder(resp.Body)
	fmt.Println("Response status:", resp.Status)

	if strings.Contains(resp.Status, "201") || strings.Contains(resp.Status, "200") {
		return nil

	} else {
		return &resp.Status
	}

}

func createSignature(c *gin.Context) {
	var bodyData struct {
		Properties Signature `json:"properties"`
	}

	c.Bind(&bodyData)

	msg := httpsClient("https://localhost/signserver/rest/v1/workers", bodyData)
	fmt.Println("Msg: ", msg)

	if msg != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": msg,
		})
	} else {
		c.JSON(http.StatusOK, gin.H{
			"message": "Create signature successfully",
		})
	}

}

func signaturePdf(c *gin.Context) {
	file, handler, err := c.Request.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Error retrieving file from form data"})
		return
	}
	defer file.Close()

	// Tạo file trống để lưu dữ liệu
	newFile, err := os.Create(handler.Filename)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error creating file"})
		return
	}
	defer newFile.Close()

	// Copy dữ liệu từ file nhận được từ client vào file trống
	_, err = io.Copy(newFile, file)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error copying file data"})
		return
	}

	fmt.Println("File uploaded successfully")

	// Gửi file sang server khác dưới dạng form data
	var requestBody bytes.Buffer
	writer := multipart.NewWriter(&requestBody)
	part, err := writer.CreateFormFile("file", handler.Filename)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error creating form file"})
		return
	}
	io.Copy(part, newFile)
	writer.Close()

	// Đặt header và gửi request sang server khác
	req, err := http.NewRequest("POST", "https://localhost/signserver/process", &requestBody)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error creating request"})
		return
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	clientTLSCert, err := tls.LoadX509KeyPair(CertFilePath, KeyFilePath)
	if err != nil {
		log.Fatalf("Error loading certificate and key file: %v", err)
		return
	}
	// Configure the client to trust TLS server certs issued by a CA.
	certPool, err := x509.SystemCertPool()
	if err != nil {
		panic(err)
	}
	if caCertPEM, err := os.ReadFile(CACertFilePath); err != nil {
		panic(err)
	} else if ok := certPool.AppendCertsFromPEM(caCertPEM); !ok {
		panic("invalid cert in CA PEM")
	}
	tlsConfig := &tls.Config{
		RootCAs:            certPool,
		Certificates:       []tls.Certificate{clientTLSCert},
		InsecureSkipVerify: true,
	}
	tr := &http.Transport{
		TLSClientConfig: tlsConfig,
	}
	client := &http.Client{Transport: tr}
	resp, err := client.Do(req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error sending request"})
		return
	}
	defer resp.Body.Close()

	// Đọc response từ server khác
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error reading response"})
		return
	}

	// Trả về response từ server khác cho client
	c.JSON(resp.StatusCode, gin.H{"response": string(responseBody)})

	return
}

func SignAPI(workername string, base64PDFstring string, signaturePosition string, positionPage string) (string, error) {

	signurl := "https://localhost/signserver/process?workerName=" + workername

	// load tls certificates
	clientTLSCert, err := tls.LoadX509KeyPair(CertFilePath, KeyFilePath)
	if err != nil {
		log.Fatalf("Error loading certificate and key file: %v", err)
		return "", err
	}
	// Configure the client to trust TLS server certs issued by a CA.
	certPool, err := x509.SystemCertPool()
	if err != nil {
		panic(err)
	}
	if caCertPEM, err := os.ReadFile(CACertFilePath); err != nil {
		panic(err)
	} else if ok := certPool.AppendCertsFromPEM(caCertPEM); !ok {
		panic("invalid cert in CA PEM")
	}
	tlsConfig := &tls.Config{
		RootCAs:            certPool,
		Certificates:       []tls.Certificate{clientTLSCert},
		InsecureSkipVerify: true,
	}
	tr := &http.Transport{
		TLSClientConfig: tlsConfig,
	}
	client := &http.Client{Transport: tr}

	//PDF start here

	//pdfFile, err := os.ReadFile("dummy.pdf")
	pdfFile := make([]byte, len(base64PDFstring)*len(base64PDFstring)/base64.StdEncoding.DecodedLen(len(base64PDFstring)))
	_, err = base64.StdEncoding.Decode(pdfFile, []byte(base64PDFstring))

	if err != nil {
		fmt.Println("Error reading PDF data:", err)
		return "", err
	}

	req, _ := http.NewRequest("POST", signurl, bytes.NewBuffer(pdfFile))

	req.Header.Set("Content-Type", "application/pdf")
	form, _ := url.ParseQuery(req.URL.RawQuery)
	// form.Add("REQUEST_METADATA.VISIBLE_SIGNATURE_RECTANGLE", "300,100,500,300")
	form.Add("REQUEST_METADATA.VISIBLE_SIGNATURE_RECTANGLE", signaturePosition)

	// form.Add("REQUEST_METADATA.VISIBLE_SIGNATURE_PAGE", "4")
	form.Add("REQUEST_METADATA.VISIBLE_SIGNATURE_PAGE", positionPage)

	req.URL.RawQuery = form.Encode()

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending HTTP request:", err)
		return "", err
	}
	defer resp.Body.Close()

	responseData, err := io.ReadAll(resp.Body)

	strToReturnToClient := base64.StdEncoding.EncodeToString(responseData)

	fmt.Println(strToReturnToClient)
	fmt.Println(len(responseData))

	if err != nil {
		fmt.Println("Error reading response body:", err)
		return "", err
	}
	err = os.WriteFile("signed8.pdf", responseData, 0644)
	if err != nil {
		fmt.Println("Error writing response to file:", err)
		return "", err
	}

	return strToReturnToClient, nil
}

func SignApiController(c *gin.Context) {
	var bodyData struct {
		WorkerName        string `json:"workername"`
		Base64PDFstring   string `json:"base64PDFstring"`
		SignaturePosition string `json:"signature_position"`
		PositionPage      string `json:"position_page"`
	}

	c.Bind(&bodyData)

	result, err := SignAPI(bodyData.WorkerName, bodyData.Base64PDFstring, bodyData.SignaturePosition, bodyData.PositionPage)

	if err != nil {
		fmt.Println("Error reading response body:", err)

		c.JSON(500, gin.H{
			"error": err,
		})

		return
	}

	c.JSON(200, gin.H{
		"status":   200,
		"response": result,
	})

}

func CORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		//use cors to prevent attack from site not belong to HODO
		//var originCors string
		//if os.Getenv("APP_ENV") == "development" {
		//	originCors = "*"
		//} else {
		//	originCors = os.Getenv("TRUSTED_ORIGINS")
		//}
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Credentials", "true")
		// c.Header("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With, X-Socket-Id")
		c.Header("Access-Control-Allow-Headers", "*")
		c.Header("Access-Control-Allow-Methods", "POST, HEAD, PATCH, OPTIONS, GET, PUT, DELETE")

		if c.Request.Method == "OPTIONS" {
			c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
			c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
			c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With, X-Socket-Id")
			c.Writer.Header().Set("Access-Control-Allow-Headers", "*")
			c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, HEAD, PATCH, OPTIONS, GET, PUT, DELETE")
			headers := c.Writer.Header()
			// In ra tất cả các header
			for key, values := range headers {
				for _, value := range values {
					fmt.Printf("Header <---------------> %s: %s\n", key, value)
				}
			}

			c.Status(200)
			return
		}

		c.Next()
	}
}

func main() {
	r := gin.Default()

	r.Use(CORSMiddleware())

	r.POST("/create-signature", createSignature)
	r.POST("/sign-document", SignApiController)

	// r.POST("/sign-document-v2", SignaturePdf)
	r.Run(":3112")
	// hello, world.
	// msg := httpsClient("https://localhost/signserver/rest/v1/workers")
	// fmt.Println("Msg: ", string(msg))
}
