package key

var (
	// Unknown Unknown whois key
	Unknown = Key(``)

	// DomainID Domain ID
	DomainID = Key(`domain-id`)

	// DomainName Domain name
	DomainName = Key(`domain`)

	// RegistrarID Registrar ID
	RegistrarID = Key(`registrar-id`)

	// RegistrarName Registrar name
	RegistrarName = Key(`registrar`)

	// WhoisServer Whois server
	WhoisServer = Key(`whois-server`)

	// ReferralURL referral url
	ReferralURL = Key(`referral-url`)

	// DomainStatus Domain status
	DomainStatus = Key(`state`)

	// NameServer Name server
	NameServer = Key(`nserver`)

	// Dnssec dnssec
	Dnssec = Key(`dnssec`)

	// Created Created date
	Created = Key(`created`)

	// Updated Updated date
	Updated = Key(`updated`)

	// PaidTill Paid-till date
	PaidTill = Key(`paid-till`)

	// Expired Expired date
	Expired = Key(`expired`)

	// FreeDate Domain free date
	FreeDate = Key(`free-date`)

	// AdminID Admin ID
	AdminID = Key(`admin-id`)

	// AdminContact Domain admin contact
	AdminContact = Key(`admin-contact`)

	// TechID Tech ID
	TechID = Key(`tech-id`)

	// BillID Bill ID
	BillID = Key(`bill-id`)

	// RegistrantID Domain registrant ID
	RegistrantID = Key(`registrant-id`)

	// RegistrantName Domain registrant
	RegistrantName = Key(`registrant`)

	// RegistrantOrganization Domain registrant organization
	RegistrantOrganization = Key(`registrant-organization`)

	// RegistrantCountry Domain registrant country
	RegistrantCountry = Key(`registrant-country`)

	// RegistrantCity Domain registrant city
	RegistrantCity = Key(`registrant-city`)

	// RegistrantProvince Domain registrant state province
	RegistrantProvince = Key(`registrant-province`)

	// RegistrantPostalCode Domain registrant postal code
	RegistrantPostalCode = Key(`registrant-postal`)

	// RegistrantStreet Domain registrant street
	RegistrantStreet = Key(`registrant-street`)

	// RegistrantPhone Domain registrant phone
	RegistrantPhone = Key(`registrant-phone`)

	// RegistrantPhoneExt Domain registrant phone extension
	RegistrantPhoneExt = Key(`registrant-phone-ext`)

	// RegistrantFax Domain registrant fax
	RegistrantFax = Key(`registrant-fax`)

	// RegistrantFaxExt Domain registrant fax extension
	RegistrantFaxExt = Key(`registrant-fax-ext`)

	// RegistrantEmail Domain registrant email
	RegistrantEmail = Key(`registrant-email`)

	// RegistrantURL Domain registrant url
	RegistrantURL = Key(`registrant-url`)

	// TechnicalHandle Registrant technical handle
	TechnicalHandle = Key(`tech-handle`)

	// TechnicalName Registrant technical name
	TechnicalName = Key(`tech-name`)

	// TechnicalPhone Registrant technical phone
	TechnicalPhone = Key(`tech-phone`)

	// TechnicalEmail Registrant technical e-mail
	TechnicalEmail = Key(`tech-email`)

	// TechnicalURL Registrant technical URL
	TechnicalURL = Key(`tech-url`)

	// AbuseHandle Registrant abuse handle
	AbuseHandle = Key(`abuse-handle`)

	// AbuseName Registrant abuse name
	AbuseName = Key(`abuse-name`)

	// AbusePhone Registrant abuse phone
	AbusePhone = Key(`abuse-phone`)

	// AbuseEmail Registrant abuse e-mail
	AbuseEmail = Key(`abuse-email`)

	// AbuseURL Registrant abuse URL
	AbuseURL = Key(`abuse-url`)

	// NetRange Network range
	NetworkRange = Key(`net-range`)

	// NetCIDR Network CIDR
	NetworkCIDR = Key(`cidr`)

	// NetworkName Network name
	NetworkName = Key(`net-name`)

	// NetworkHandle Network handle
	NetworkHandle = Key(`net-handle`)

	// NetworkParent Parent network
	NetworkParent = Key(`parent`)

	// NetworkType Network type
	NetworkType = Key(`net-type`)

	// NetworkMountBy Network mnt-by
	NetworkMountBy = Key(`mnt-by`)

	// NetworkNicHandle Personal nic hndl code
	NetworkNicHandle = Key(`nic-hdl`)

	// OriginAS Origin AS
	OriginAS = Key(`origin-as`)

	// Comment string
	Comment = Key(`comment`)
)

// Key Known whois key
type Key string

var keyMap = map[string]Key{
	"":                                       Unknown,
	"id":                                     DomainID,
	"roid":                                   DomainID,
	"domain id":                              DomainID,
	"registry domain id":                     DomainID,
	"domain":                                 DomainName,
	"domain name":                            DomainName,
	"registrar id":                           RegistrarID,
	"registrar iana id":                      RegistrarID,
	"sponsoring registrar iana id":           RegistrarID,
	"registrar":                              RegistrarName,
	"registrar name":                         RegistrarName,
	"sponsoring registrar":                   RegistrarName,
	"last updated by registrar":              RegistrarName,
	"authorized agency":                      RegistrarName,
	"source":                                 RegistrarName,
	"whois server":                           WhoisServer,
	"registrar whois server":                 WhoisServer,
	"referral url":                           ReferralURL,
	"registrar url":                          ReferralURL,
	"ref":                                    ReferralURL,
	"status":                                 DomainStatus,
	"state":                                  DomainStatus,
	"domain status":                          DomainStatus,
	"registration status":                    DomainStatus,
	"nserver":                                NameServer,
	"name server":                            NameServer,
	"nameservers":                            NameServer,
	"name servers":                           NameServer,
	"name servers information":               NameServer,
	"host name":                              NameServer,
	"dnssec":                                 Dnssec,
	"domain dnssec":                          Dnssec,
	"created":                                Created,
	"registered":                             Created,
	"create date":                            Created,
	"created on":                             Created,
	"creation date":                          Created,
	"domain registration date":               Created,
	"registration date":                      Created,
	"domain create date":                     Created,
	"domain name commencement date":          Created,
	"registered date":                        Created,
	"registered on":                          Created,
	"registration time":                      Created,
	"regdate":                                Created,
	"reg date":                               Created,
	"paid-till":                              PaidTill,
	"modified":                               Updated,
	"changed":                                Updated,
	"update date":                            Updated,
	"updated date":                           Updated,
	"updated on":                             Updated,
	"last update":                            Updated,
	"last updated":                           Updated,
	"last updated on":                        Updated,
	"last modified":                          Updated,
	"last updated date":                      Updated,
	"domain last updated date":               Updated,
	"updated":                                Updated,
	"last-modified":                          Updated,
	"expire":                                 Expired,
	"expires":                                Expired,
	"expires on":                             Expired,
	"paid till":                              Expired,
	"expire date":                            Expired,
	"expired date":                           Expired,
	"expiration date":                        Expired,
	"expiration on":                          Expired,
	"registry expiry date":                   Expired,
	"registrar registration expiration date": Expired,
	"domain expiration date":                 Expired,
	"expiry date":                            Expired,
	"expiration time":                        Expired,
	"free-date":                              FreeDate,
	"registry admin id":                      AdminID,
	"admin-contact":                          AdminContact,
	"admin contact":                          AdminContact,
	"registry tech id":                       TechID,
	"registry bill id":                       BillID,
	"registry registrant id":                 RegistrantID,
	"registrant c":                           RegistrantID,
	"registrant id":                          RegistrantID,
	"registrant contact id":                  RegistrantID,
	"orgid":                                  RegistrantID,
	"org id":                                 RegistrantID,
	"admin-c":                                RegistrantID,
	"rnochandle":                             RegistrantID,
	"registrant":                             RegistrantName,
	"registrant name":                        RegistrantName,
	"registrant contact":                     RegistrantName,
	"registrant contact name":                RegistrantName,
	"person":                                 RegistrantName,
	"rnocname":                               RegistrantName,
	"registrant organization":                RegistrantOrganization,
	"registrant contact organization":        RegistrantOrganization,
	"orgname":                                RegistrantOrganization,
	"org name":                               RegistrantOrganization,
	"org":                                    RegistrantOrganization,
	"organization":                           RegistrantOrganization,
	"registrant country":                     RegistrantCountry,
	"registrant country economy":             RegistrantCountry,
	"registrant contact country":             RegistrantCountry,
	"country":                                RegistrantCountry,
	"registrant city":                        RegistrantCity,
	"registrant contact city":                RegistrantCity,
	"city":                                   RegistrantCity,
	"registrant state province":              RegistrantProvince,
	"registrant contact state province":      RegistrantProvince,
	"stateprov":                              RegistrantProvince,
	"state prov":                             RegistrantProvince,
	"registrant postal code":                 RegistrantPostalCode,
	"registrant contact postal code":         RegistrantPostalCode,
	"postalcode":                             RegistrantPostalCode,
	"postal code":                            RegistrantPostalCode,
	"registrant street":                      RegistrantStreet,
	"registrant contact street":              RegistrantStreet,
	"registrant address1":                    RegistrantStreet,
	"registrant street1":                     RegistrantStreet,
	"registrant contact address1":            RegistrantStreet,
	"registrant s address":                   RegistrantStreet,
	"address":                                RegistrantStreet,
	"descr":                                  RegistrantStreet,
	"registrant phone":                       RegistrantPhone,
	"registrant phone number":                RegistrantPhone,
	"registrant contact phone":               RegistrantPhone,
	"registrant contact phone number":        RegistrantPhone,
	"registrar abuse contact phone":          RegistrantPhone,
	"phone":                                  RegistrantPhone,
	"rnocphone":                              RegistrantPhone,
	"registrant phone ext":                   RegistrantPhoneExt,
	"registrant contact phone ext":           RegistrantPhoneExt,
	"registrant fax":                         RegistrantFax,
	"registrant fax number":                  RegistrantFax,
	"registrant facsimile":                   RegistrantFax,
	"registrant facsimile number":            RegistrantFax,
	"registrant contact fax":                 RegistrantFax,
	"registrant contact fax number":          RegistrantFax,
	"registrant contact facsimile":           RegistrantFax,
	"registrant contact facsimile number":    RegistrantFax,
	"fax-no":                                 RegistrantFax,
	"registrant fax ext":                     RegistrantFaxExt,
	"registrant contact fax ext":             RegistrantFaxExt,
	"registrant mail":                        RegistrantEmail,
	"registrant email":                       RegistrantEmail,
	"registrant e mail":                      RegistrantEmail,
	"registrant contact mail":                RegistrantEmail,
	"registrant contact email":               RegistrantEmail,
	"registrant contact e mail":              RegistrantEmail,
	"registrar abuse contact email":          RegistrantEmail,
	"rnocemail":                              RegistrantEmail,
	"admin email":                            RegistrantEmail,
	"rnocref":                                RegistrantURL,
	"orgtechhandle":                          TechnicalHandle,
	"org tech handle":                        TechnicalHandle,
	"tech-c":                                 TechnicalHandle,
	"rtechhandle":                            TechnicalHandle,
	"orgtechname":                            TechnicalName,
	"org tech name":                          TechnicalName,
	"rtechname":                              TechnicalName,
	"orgtechphone":                           TechnicalPhone,
	"org tech phone":                         TechnicalPhone,
	"rtechphone":                             TechnicalPhone,
	"orgtechemail":                           TechnicalEmail,
	"org tech email":                         TechnicalEmail,
	"rtechemail":                             TechnicalEmail,
	"tech email":                             TechnicalEmail,
	"orgtechref":                             TechnicalURL,
	"org tech ref":                           TechnicalURL,
	"rtechref":                               TechnicalURL,
	"orgabusehandle":                         AbuseHandle,
	"org abuse handle":                       AbuseHandle,
	"rabusehandle":                           AbuseHandle,
	"orgabusename":                           AbuseName,
	"org abuse name":                         AbuseName,
	"rabusename":                             AbuseName,
	"orgabusephone":                          AbusePhone,
	"org abuse phone":                        AbusePhone,
	"rabusephone":                            AbusePhone,
	"orgabuseemail":                          AbuseEmail,
	"org abuse email":                        AbuseEmail,
	"rabuseemail":                            AbuseEmail,
	"orgabuseref":                            AbuseURL,
	"org abuse ref":                          AbuseURL,
	"rabuseref":                              AbuseURL,
	"netrange":                               NetworkRange,
	"net range":                              NetworkRange,
	"inetnum":                                NetworkRange,
	"cidr":                                   NetworkCIDR,
	"netname":                                NetworkName,
	"net name":                               NetworkName,
	"nethandle":                              NetworkHandle,
	"net handle":                             NetworkHandle,
	"parent":                                 NetworkParent,
	"route":                                  NetworkParent,
	"nettype":                                NetworkType,
	"net type":                               NetworkType,
	"mnt-by":                                 NetworkMountBy,
	"mnt by":                                 NetworkMountBy,
	"nic-hdl":                                NetworkNicHandle,
	"nic hdl":                                NetworkNicHandle,
	"originas":                               OriginAS,
	"origin as":                              OriginAS,
	"origin":                                 OriginAS,
	"comment":                                Comment,
}
