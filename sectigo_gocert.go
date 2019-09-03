package sectigo_gocert

import (
		"github.com/hashicorp/terraform/helper/schema"
		"log"
		"crypto/x509"
		"crypto/x509/pkix"
		"fmt"
		"crypto/rand"
		"crypto/rsa"
		"encoding/asn1"
		"encoding/pem"
		"os"
		"io/ioutil"
		"strings"
		"net/http"
		"bytes"
		"encoding/json"
		"strconv"
		"time"

		"crypto/ecdsa"
		"crypto/elliptic"
		// "flag"
)

// To get the SSLID from Enroll Cert Response Status
type EnrollResponseType struct {
	RenewId string `json:"renewId"`
	SslIdVal int   `json:"sslId"`
}

// To get the SSLID from Enroll Cert Response Status
type DownloadResponseType struct {
	DlCode int `json:"code"`
	Desc string   `json:"description"`
}

var oidemail_address = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}

// PEM Block for Key Generation
func pemBlockForKey(priv interface{}) *pem.Block {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to marshal ECDSA private key: %v", err)
			os.Exit(2)
		}
		return &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}
	default:
		return nil
	}
}

// Generate Key
func GenerateKey(d *schema.ResourceData, m interface{}, FilesArr map[string]bool) (*rsa.PrivateKey, *ecdsa.PrivateKey, string) {

	domain := d.Get("domain").(string)
	cert_file_name := d.Get("cert_file_name").(string)
	cert_file_path := d.Get("cert_file_path").(string)
	var priv interface{}
	var err error

	var signAlgType = d.Get("sign_algorithm_type").(string)
	var rsaBits = d.Get("rsa_bits").(int)
	var curvelength = d.Get("curve_length").(string)

	log.Println("Generating KEY for "+domain)
	WriteLogs(d,"Generating KEY for "+domain)
	log.Println("signAlgType: "+signAlgType)

	if signAlgType == "RSA" {
		priv, err = rsa.GenerateKey(rand.Reader, rsaBits)
	} else if signAlgType == "ECDSA" {
		if curvelength == "P224" {
			priv, err = ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
		} else if curvelength == "P256" {
			priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		} else if curvelength == "P384" {
			priv, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		} else if curvelength == "P521" {
			priv, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		} else {
			fmt.Fprintf(os.Stderr, "Unrecognized elliptic curve: %q", signAlgType)
			os.Exit(1)
		}
	}
	if err != nil {
		log.Fatalf("failed to generate private key: %s", err)
		WriteLogs(d,"failed to generate private key: %s"+err.Error())
	}

	// Write key to file
	keyOut, err := os.OpenFile(cert_file_path+cert_file_name+".key", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Print("Failed to open key.pem for writing:", err)
		WriteLogs(d,"Failed to open key.pem for writing: "+err.Error())
		CleanUp(d,FilesArr)
		os.Exit(1)
	}
	if err := pem.Encode(keyOut, pemBlockForKey(priv)); err != nil {
		log.Fatalf("Failed to write data to key.pem: %s", err)
		WriteLogs(d,"Failed to write data to key.pem: "+err.Error())
		CleanUp(d,FilesArr)
		os.Exit(1)
	}
	if err := keyOut.Close(); err != nil {
		log.Fatalf("Error closing key.pem: %s", err)
		WriteLogs(d,"Error closing key.pem: "+err.Error())
		CleanUp(d,FilesArr)
		os.Exit(1)
	}

	//Read Key from file and put it in the tfstate
	keyVal, err := ioutil.ReadFile(cert_file_path+cert_file_name+".key")
	if err != nil {
		log.Println("Failed to read the key from file:", err)
		WriteLogs(d,"Failed to read the key from file:"+ err.Error())
		CleanUp(d,FilesArr)
		os.Exit(1)
	}
	
	if signAlgType == "RSA" {
		return priv.(*rsa.PrivateKey), nil, string(keyVal)
	} else {
		return nil, priv.(*ecdsa.PrivateKey), string(keyVal)
	}
	return nil, nil, ""
}

// Get SignAlgorithm to generate CSR
func getSignAlgorithm(signAlgType string, rsaBits int, curvelength string) x509.SignatureAlgorithm {
	if signAlgType == "RSA" {
		if rsaBits == 4096 {
			return x509.SHA512WithRSA
		} else if rsaBits == 3072 {
			return x509.SHA384WithRSA
		} else if rsaBits == 2048 {
			return x509.SHA256WithRSA
		} else {
			return x509.SHA1WithRSA
		} 
	} else if signAlgType == "ECDSA" {
		if curvelength == "P521" {
			return x509.ECDSAWithSHA512
		} else if curvelength == "P384" {
			return x509.ECDSAWithSHA384
		} else if curvelength == "P256" {
			return x509.ECDSAWithSHA256
		} else {
			return x509.ECDSAWithSHA1
		}
	}
	return x509.UnknownSignatureAlgorithm
}
	
// Generate CSR
func GenerateCSR(d *schema.ResourceData, m interface{}, keyBytesRSA *rsa.PrivateKey, keyBytesECDSA *ecdsa.PrivateKey, FilesArr map[string]bool) (string) {

	var signAlgType = d.Get("sign_algorithm_type").(string)
	var rsaBits = d.Get("rsa_bits").(int)
	var curvelength = d.Get("curve_length").(string)

	domain := d.Get("domain").(string)
	cert_file_name := d.Get("cert_file_name").(string)
	cert_file_path := d.Get("cert_file_path").(string)

	log.Println("Generating CSR forr "+domain)
	WriteLogs(d,"Generating CSR forr "+domain)

	getSignAlgorithm := getSignAlgorithm(signAlgType, rsaBits, curvelength)

	subj := pkix.Name{
        CommonName:         domain,
        Country:            []string{d.Get("country").(string)},
        Province:           []string{d.Get("province").(string)},
        Locality:           []string{d.Get("locality").(string)},
        Organization:       []string{d.Get("organization").(string)},
        OrganizationalUnit:	[]string{d.Get("org_unit").(string)},
        ExtraNames: []pkix.AttributeTypeAndValue{
            {
                Type:  oidemail_address, 
                Value: asn1.RawValue{
                    Tag:   asn1.TagIA5String, 
                    Bytes: []byte(d.Get("email_address").(string)),
                },
            },
        },
    }

    template := x509.CertificateRequest{
        Subject:            subj,
		SignatureAlgorithm: getSignAlgorithm, //x509.ECDSAWithSHA256,
		DNSNames:			[]string{d.Get("subject_alt_names").(string)} ,
    }

	// Put CSR in a file 
    csrOut, err := os.Create(cert_file_path+cert_file_name+".csr")
    if err != nil {
		log.Println("Failed to open CSR for writing:", err)
		WriteLogs(d,"Failed to open CSR for writing:"+err.Error())
		CleanUp(d,FilesArr)
        os.Exit(1)
    }

	if signAlgType == "RSA" {
		csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, keyBytesRSA)
		if err != nil {
			log.Println("Failed to Generate CSR for ECDSA:", err)
			WriteLogs(d,"Failed to Generate CSR for ECDSA :"+err.Error())
			CleanUp(d,FilesArr)
			os.Exit(1)
		}
		pem.Encode(csrOut, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})
	} else if signAlgType == "ECDSA" {
		csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, keyBytesECDSA)		
		if err != nil {
			log.Println("Failed to Generate CSR for ECDSA:", err)
			WriteLogs(d,"Failed to Generate CSR for ECDSA :"+err.Error())
			os.Exit(1)
		}
		pem.Encode(csrOut, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})
	}
	csrOut.Close()

	//Read CSR from file and put it in the tfstate
	csrVal, err := ioutil.ReadFile(cert_file_path+cert_file_name+".csr")
	if err != nil {
		log.Println("Failed to write CSR to a file:", err)
		WriteLogs(d,"Failed to write CSR to a file:"+err.Error())
        os.Exit(1)
    }
	var csrString = strings.Replace(string(csrVal),"\n","",-1)
	return csrString
}

func CheckCertValidity(d *schema.ResourceData, FilesArr map[string]bool) bool {
	cert_file_name := d.Get("cert_file_name").(string)
	cert_file_path := d.Get("cert_file_path").(string)
	certPEM, err := ioutil.ReadFile(cert_file_path+cert_file_name+".crt")
	if err != nil {
		log.Println("Failed to write CSR to a file:", err)
		WriteLogs(d,"Failed to write CSR to a file:"+err.Error())
        os.Exit(1)
	}

	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		panic("Failed to parse certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic("failed to parse certificate: " + err.Error())
	}

	now := time.Now()	
	warningDays := d.Get("cert_warning_days").(int)
	expiryDate := cert.NotAfter
	warningDate := expiryDate.AddDate(0, 0,(warningDays*-1))

	log.Println("==================")
	log.Println("Current Date: ", now)
	log.Println("Warning Date: ", warningDate)
	log.Println("Expiry Date:  ", expiryDate)
	WriteLogs(d,"Current Date: "+ now.Format("2006-01-02 15:04:05"))
	WriteLogs(d,"Warning Date: "+ warningDate.Format("2006-01-02 15:04:05"))
	WriteLogs(d,"Expiry Date:  "+ expiryDate.Format("2006-01-02 15:04:05"))

	//if now.Before(expiryDate) && now.After(warningDate) {	
	if now.After(warningDate) {		// if current date is after the warning date
		return false
	} else {
		return true
	}
	return false
}

// Enroll Cert
func EnrollCert(d *schema.ResourceData,csrVal string, customerArr map[string]string, FilesArr map[string]bool) (int,string) {
	domain := d.Get("domain").(string)
	var sslId = 0
	var renewId = ""
	url := d.Get("sectigo_ca_base_url").(string)+"enroll"
	var jsonStr = []byte("{\"orgId\":"+strconv.Itoa(d.Get("sectigo_cm_orgid").(int))+",\"csr\":\""+csrVal+"\",\"certType\":"+strconv.Itoa(d.Get("cert_type").(int))+",\"numberServers\":"+strconv.Itoa(d.Get("cert_num_servers").(int))+",\"serverType\":"+strconv.Itoa(d.Get("server_type").(int))+",\"term\":"+strconv.Itoa(d.Get("cert_validity").(int))+",\"comments\":\""+d.Get("cert_comments").(string)+"\",\"externalRequester\":\""+d.Get("cert_ext_requester").(string)+"\",\"subjAltNames\":\""+d.Get("subject_alt_names").(string)+"\"}")	

	log.Println("Enrolling CERT for "+domain)
	WriteLogs(d,"Enrolling CERT for "+domain)

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonStr))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Login", customerArr["username"])
	req.Header.Set("Password", customerArr["password"])
	req.Header.Set("Customeruri", customerArr["customer_uri"])
    if err != nil {
		log.Println(err)
		WriteLogs(d,err.Error())
		CleanUp(d,FilesArr)
		os.Exit(1)
    }

    client := &http.Client{}
    resp, err := client.Do(req)
    if err != nil {
		log.Println(err)
		WriteLogs(d,err.Error())
		CleanUp(d,FilesArr)
		os.Exit(1)
    }
    defer resp.Body.Close()

    enrollResponse, err := ioutil.ReadAll(resp.Body)
    if err != nil {
		//panic(err)
		log.Println(err)
		WriteLogs(d,err.Error())
		CleanUp(d,FilesArr)
		os.Exit(1)
    }
	log.Println("Response Status:", resp.Status)
    log.Println("Enroll Response:", string(enrollResponse))
	WriteLogs(d,"Response Status:"+ resp.Status)
	WriteLogs(d,"Enroll Response:"+ string(enrollResponse))

	var enrollStatus = strings.Contains(resp.Status, "200")
	var sslIdStatus = strings.Contains(string(enrollResponse), "sslId")
	if enrollStatus && sslIdStatus {
		log.Println("Certificate succesfully Enrolled...")
		WriteLogs(d,"Certificate succesfully Enrolled...")
		
		// Fetch ssl id from response json
		var enrollResponseJson = []byte(string(enrollResponse))
		var enr EnrollResponseType
		json.Unmarshal(enrollResponseJson, &enr)
		sslId = enr.SslIdVal
		renewId = enr.RenewId
		if(string(sslId) != "" && sslId > 0) {
			log.Println(sslId)
			WriteLogs(d,strconv.Itoa(sslId))
		} else {
			log.Println("SSLID Generation Failed... Exiting..."+string(enrollResponse))
			WriteLogs(d,"SSLID Generation Failed... Exiting..."+string(enrollResponse))
			CleanUp(d,FilesArr)
			os.Exit(1)
		}
	} else {
		log.Println("Certificate Enrollment Failed... Exiting..."+string(enrollResponse))
		WriteLogs(d,"Certificate Enrollment Failed... Exiting..."+string(enrollResponse))
		CleanUp(d,FilesArr)
		os.Exit(1)
	}
	return sslId,renewId
}

// DOWNLOAD CERT 
func DownloadCert(sslId int, d *schema.ResourceData, customerArr map[string]string, timer int, FilesArr map[string]bool) string {
	max_timeout := d.Get("max_timeout").(int)
	domain := d.Get("domain").(string)
	cert_file_name := d.Get("cert_file_name").(string)
	cert_file_path := d.Get("cert_file_path").(string)
	url := d.Get("sectigo_ca_base_url").(string)+"collect/"+strconv.Itoa(sslId)+"/x509CO"

	log.Println("\n---------DOWNLOAD CERT for "+domain+"---------")
	log.Println(url)
	WriteLogs(d,"---------DOWNLOAD CERT for "+domain+"---------")
	WriteLogs(d,url)

	req, err := http.NewRequest("GET", url, nil)	
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Login", customerArr["username"])
	req.Header.Set("Password", customerArr["password"])
	req.Header.Set("Customeruri", customerArr["customer_uri"])

	client := &http.Client{}
    resp, err := client.Do(req)
    if err != nil {
		log.Println(err)
		WriteLogs(d,err.Error())
		CleanUp(d,FilesArr)
		os.Exit(1)
    }
    defer resp.Body.Close()

    downloadResponse, _ := ioutil.ReadAll(resp.Body)
	log.Println("Response Status:", resp.Status)
    log.Println("Download Response:", string(downloadResponse))
	WriteLogs(d,"Response Status:"+ resp.Status)
	WriteLogs(d,"Download Response:"+ string(downloadResponse))
	
	// Fetch code and reason from downloadresponse json
	var downloadResponseJson = []byte(string(downloadResponse))
	var dl DownloadResponseType
	json.Unmarshal(downloadResponseJson, &dl)
	var dlCode = dl.DlCode
	if(dlCode != 0) && (dlCode != -1400) {
		return "ErrorCode"
	} else {
		var downloadStatus = strings.Contains(resp.Status, "200")
		if downloadStatus {				// if 200 found in code... cert available for download
			// Write crt to file		
			f, err := os.Create(cert_file_path+cert_file_name+".crt")
			if err != nil {
				log.Println(err)
				WriteLogs(d,err.Error())
				CleanUp(d,FilesArr)
				os.Exit(1)
			}
			l, err := f.WriteString(string(downloadResponse))
			if err != nil {
				log.Println(err)
				WriteLogs(d,err.Error())
				f.Close()
				CleanUp(d,FilesArr)
				os.Exit(1)
			}
			log.Println(l, "bytes written successfully")
			err = f.Close()
			if err != nil {
				log.Println(err)
				WriteLogs(d,err.Error())
				CleanUp(d,FilesArr)
				os.Exit(1)
			}
			return string(downloadResponse)
		} else {						// code does not have 200.. not 
			timer = timer + d.Get("loop_period").(int)
			log.Println("Waiting for "+strconv.Itoa(timer)+" / "+strconv.Itoa(max_timeout)+" seconds before the next download attempt...")
			WriteLogs(d,"Waiting for "+strconv.Itoa(timer)+" / "+strconv.Itoa(max_timeout)+" seconds before the next download attempt...")
			time.Sleep(time.Duration(d.Get("loop_period").(int)) * time.Second)
			
			if(timer >= max_timeout){	// if Wait time crosses Timeout... save and exit	
				log.Println("Timed out!! Waited for "+strconv.Itoa(timer)+"/"+strconv.Itoa(max_timeout)+" seconds. You can increase/decrease the timeout period (in seconds) in the tfvars file")
				log.Println("Download Response:", string(downloadResponse))
				WriteLogs(d,"Timed out!! Waited for "+strconv.Itoa(timer)+"/"+strconv.Itoa(max_timeout)+" seconds. You can increase/decrease the timeout period (in seconds) in the tfvars file")
				WriteLogs(d,"Download Response:"+string(downloadResponse))
	
				if(dlCode == 0) || (dlCode == -1400) {
					return "TimedOutStateSaved"				
				} else {
					return "ErrorCode"				
				}
			} else {
				return DownloadCert(sslId,d,customerArr,timer,FilesArr)
			}
		}	
	}
	
	return string(downloadResponse)
}

// // Renew Certificate
// func RenewCertificate(d *schema.ResourceData,customerArr map[string]string) (string,int) {
// 	renewId := d.Get("sectigo_renew_id").(string)
// 	url := d.Get("sectigo_ca_base_url").(string)+"renew/"+renewId
// 	log.Println(url)
// 	WriteLogs(d,url)
// 	var jsonStr = []byte("{\"reason\":\"Terraform Certificate Renew. Current Renew ID: "+renewId+"\"}")

// 	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonStr))
//     if err != nil {
// 		log.Println(err)
// 		WriteLogs(d,err.Error())
// 		os.Exit(1)
//     }
// 	req.Header.Set("Content-Type", "application/json")
// 	req.Header.Set("Login", customerArr["username"])
// 	req.Header.Set("Password", customerArr["password"])
// 	req.Header.Set("Customeruri", customerArr["customer_uri"])

//     client := &http.Client{}
//     resp, err := client.Do(req)
//     if err != nil {
// 		log.Println(err)
// 		WriteLogs(d,err.Error())
// 		CleanUp(d,FilesArr)
// 		os.Exit(1)
//     }
//     defer resp.Body.Close()

// 	renewResponse, err := ioutil.ReadAll(resp.Body)
// 	if err != nil {
// 		log.Println(err)
// 		WriteLogs(d,err.Error())
// 		CleanUp(d,FilesArr)
// 		os.Exit(1)
//     }
// 	log.Println("Renew Response Status:", resp.Status)
//     log.Println("Renew Response:", string(renewResponse))
// 	WriteLogs(d,"Renew Response Status:"+ resp.Status)
//     WriteLogs(d,"Renew Response:"+string(renewResponse))

// 	var newRenewId = ""
// 	var newSslId = 0
// 	var renewStatus = strings.Contains(resp.Status, "204")
// 	if renewStatus  {
// 		// Fetch ssl id from response json
// 		var renewResponseJson = []byte(string(renewResponse))
// 		var enr EnrollResponseType
// 		json.Unmarshal(renewResponseJson, &enr)
// 		newSslId = enr.SslIdVal
// 		newRenewId = enr.RenewId
// 		log.Println("Certificate successfully Renewed...")
// 		WriteLogs(d,"Certificate successfully Renewed...")
// 	} else {
// 		os.Exit(1)
// 	}
// 	return newRenewId, newSslId
// }

// Revoke Certificate 
func RevokeCertificate(sslId int, d *schema.ResourceData, customerArr map[string]string, FilesArr map[string]bool) (bool, error) {
	var flg = false 
	url := d.Get("sectigo_ca_base_url").(string)+"revoke/"+strconv.Itoa(sslId)
	log.Println(url)
	WriteLogs(d,url)
	var jsonStr = []byte("{\"reason\":\"Terraform destroy\"}")

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonStr))
    if err != nil {
		log.Println(err)
		WriteLogs(d,err.Error())
		os.Exit(1)
    }
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Login", customerArr["username"])
	req.Header.Set("Password", customerArr["password"])
	req.Header.Set("Customeruri", customerArr["customer_uri"])

    client := &http.Client{}
    resp, err := client.Do(req)
    if err != nil {
		log.Println(err)
		WriteLogs(d,err.Error())
		CleanUp(d,FilesArr)
		os.Exit(1)
    }
    defer resp.Body.Close()

	revokeResponse, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Println(err)
		WriteLogs(d,err.Error())
		CleanUp(d,FilesArr)
		os.Exit(1)
    }
	log.Println("Revoke Response Status:", resp.Status)
    log.Println("Revoke Response:", string(revokeResponse))
	WriteLogs(d,"Revoke Response Status:"+ resp.Status)
    WriteLogs(d,"Revoke Response:"+string(revokeResponse))

	var revokeStatus = strings.Contains(resp.Status, "204")
	if revokeStatus  {
		log.Println("Certificate successfully Revoked...")
		WriteLogs(d,"Certificate successfully Revoked...")
		CleanUp(d,FilesArr)
		flg = true
	} else {
		os.Exit(1)
	}
	return flg, err
}

// Get Env value
func GetProviderEnvValue(d *schema.ResourceData,param string, envParam string) string {

	val := os.Getenv(envParam)
	if val == ""  {
		log.Println(param+" Variable \""+envParam+"\" not set or empty. Please set the password in TFVARS file or as Environment Variable and try again.")
		WriteLogs(d,param+" Variable \""+envParam+"\" not set or empty. Please set the password in TFVARS file or as Environment Variable and try again.")
		os.Exit(1)
	} 
	val = strings.Replace(string(val),"\r","",-1)
	return string(val)
}

// Get Param value
func GetParamValue(d *schema.ResourceData,param string, envParam string) string {

	val1 := d.Get(param).(string)
	if (val1 == "") {
		val2, exists := os.LookupEnv(envParam)
		if val2 == "" || !exists {
			log.Println(param+" Variable \""+envParam+"\" not set or empty. Please set the password in TFVARS file or as Environment Variable and try again.")
			WriteLogs(d,param+" Variable \""+envParam+"\" not set or empty. Please set the password in TFVARS file or as Environment Variable and try again.")
			os.Exit(1)
		} else{
			val1 = val2
		}		
	} 
	val := strings.Replace(string(val1),"\r","",-1)
	return val
}

// Write Logs to a file
func WriteLogs(d *schema.ResourceData,log string){
	current := time.Now()
	cert_file_path := d.Get("cert_file_path").(string)
	cert_file_name := d.Get("cert_file_name").(string)
		
	// If the file doesn't exist, create it, or append to the file
	file, err := os.OpenFile(cert_file_path+cert_file_name+".log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println(err)
	}
	if _, err := file.Write([]byte(current.Format("2006-01-02 15:04:05")+" "+log+"\n")); err != nil {
		fmt.Println(err)
	}
	if err := file.Close(); err != nil {
		fmt.Println(err)
	}	
}

// Clean up the previous files
func CleanUp(d *schema.ResourceData, FilesArr map[string]bool, params ...string){
	cert_file_name := d.Get("cert_file_name").(string)
	cert_file_path := d.Get("cert_file_path").(string)

	if len(params) > 0 {
		var old_cert_file_name = params[0]
		os.Remove(cert_file_path+old_cert_file_name+".csr")
		os.Remove(cert_file_path+old_cert_file_name+".crt")
		os.Remove(cert_file_path+old_cert_file_name+".key")
		log.Println("Deleting any previous CSR/KEY/CERT that was generated")
		WriteLogs(d,"Deleting any previous CSR/KEY/CERT that was generated")
	} else{
		os.Remove(cert_file_path+cert_file_name+".csr")
		os.Remove(cert_file_path+cert_file_name+".crt")
		os.Remove(cert_file_path+cert_file_name+".key")	
		log.Println("Could not complete the process. Deleting any CSR/KEY/CERT that was generated")
		WriteLogs(d,"Could not complete the process. Deleting any CSR/KEY/CERT that was generated")
	}

}

// Returns whether the given file or directory exists
func PathExists(path string) (bool, error) {
    _, err := os.Stat(path)
    if err == nil { return true, nil }
    if os.IsNotExist(err) { return false, nil }
    return true, err
}