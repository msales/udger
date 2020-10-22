package udger

import (
	"database/sql"

	"github.com/glenn-brown/golang-pkg-pcre/src/pkg/pcre"
	_ "github.com/mattn/go-sqlite3"
)

// Udger contains the data and exposes the Lookup(ua string) function
type Udger struct {
	db               *sql.DB
	rexBrowsers      []rexData
	rexDevices       []rexData
	rexOS            []rexData
	browserTypes     map[int]string
	browserOS        map[int]int
	Browsers         map[int]Browser
	OS               map[int]OS
	Devices          map[int]Device
	IP               map[string]IP
	IPClass          map[int]IPClass
	Crawler          map[int]Crawler
	CrawlerClass     map[int]CrawlerClass
	DataCenter       map[int]DataCenter
	DataCenterRange  []DataCenterRange
	DataCenterRange6 []DataCenterRange6
}

// Info is the struct returned by the Lookup(ua string) function, contains everything about the UA
type Info struct {
	Browser Browser `json:"browser"`
	OS      OS      `json:"os"`
	Device  Device  `json:"device"`
}

// Browser contains information about the browser type, engine and off course it's name
type Browser struct {
	Name    string `json:"name"`
	Family  string `json:"family"`
	Version string `json:"version"`
	Engine  string `json:"engine"`
	typ     int
	Type    string `json:"type"`
	Company string `json:"company"`
	Icon    string `json:"icon"`
}

type rexData struct {
	ID            int
	Regex         string
	RegexCompiled pcre.Regexp
}

// OS contains all the information about the operating system
type OS struct {
	Name    string `json:"name"`
	Family  string `json:"family"`
	Icon    string `json:"icon"`
	Company string `json:"company"`
}

// Device contains all the information about the device type
type Device struct {
	Name string `json:"name"`
	Icon string `json:"icon"`
}

type IPInfo struct {
	IP               IP               `json:"ip"`
	IPClass          IPClass          `json:"ip_class"`
	Crawler          Crawler          `json:"crawler"`
	CrawlerClass     CrawlerClass          `json:"crawler_class"`
	DataCenter       DataCenter       `json:"data_center"`
	DataCenterRange  DataCenterRange  `json:"data_center_range"`
	DataCenterRange6 DataCenterRange6 `json:"data_center_range6"`
}

// Device contains all the information about the device type
type IP struct {
	IP            string `json:"ip"`
	ClassID       int    `json:"class_id"`
	CrawlerID     int    `json:"crawler_id"`
	IPLastSeen    string `json:"ip_last_seen"`
	IPHostname    string `json:"ip_hostname"`
	IPCountry     string `json:"ip_country"`
	IPCity        string `json:"ip_city"`
	IPCountryCode string `json:"ip_country_code"`
}

type Crawler struct {
	ID               int    `json:"id"`
	UA               string `json:"ua_string"`
	Ver              string `json:"ver"`
	VerMajor         string `json:"ver_major"`
	ClassID          int    `json:"class_id"`
	LastSeen         string `json:"last_seen"`
	RespectRobotstxt string `json:"respect_robotstxt"`
	Family           string `json:"family"`
	FamilyCode       string `json:"family_code"`
	FamilyHomepage   string `json:"family_homepage"`
	FamilyIcon       string `json:"family_icon"`
	Vendor           string `json:"vendor"`
	VendorCode       string `json:"vendor_code"`
	VendorHomepage   string `json:"vendor_homepage"`
	Name             string `json:"name"`
}

type IPClass struct {
	ID                   int    `json:"id"`
	IPClassification     string `json:"ip_classification"`
	IPClassificationCode string `json:"ip_classification_code"`
}

type CrawlerClass struct {
	ID                        int    `json:"id"`
	CrawlerClassification     string `json:"crawler_classification"`
	CrawlerClassificationCode string `json:"crawler_classification_code"`
}

type DataCenter struct {
	ID       int    `json:"id"`
	Name     string `json:"name"`
	NameCode string `json:"name_code"`
	Homepage string `json:"homepage"`
}

type DataCenterRange struct {
	DatacenterID int    `json:"datacenter_id"`
	IPFrom       string `json:"ip_from"`
	IPTo         string `json:"ip_to"`
	IPLongFrom   int    `json:"iplong_from"`
	IPLongTo     int    `json:"iplong_to"`
}

type DataCenterRange6 struct {
	DatacenterID int    `json:"datacenter_id"`
	IPFrom       string `json:"ip_from"`
	IPTo         string `json:"ip_to"`
	IPLongFrom0  int    `json:"iplong_from0"`
	IPLongFrom1  int    `json:"iplong_from1"`
	IPLongFrom2  int    `json:"iplong_from2"`
	IPLongFrom3  int    `json:"iplong_from3"`
	IPLongFrom4  int    `json:"iplong_from4"`
	IPLongFrom5  int    `json:"iplong_from5"`
	IPLongFrom6  int    `json:"iplong_from6"`
	IPLongFrom7  int    `json:"iplong_from7"`
	IPLongTo0    int    `json:"iplong_to0"`
	IPLongTo1    int    `json:"iplong_to1"`
	IPLongTo2    int    `json:"iplong_to2"`
	IPLongTo3    int    `json:"iplong_to3"`
	IPLongTo4    int    `json:"iplong_to4"`
	IPLongTo5    int    `json:"iplong_to5"`
	IPLongTo6    int    `json:"iplong_to6"`
	IPLongTo7    int    `json:"iplong_to7"`
}
