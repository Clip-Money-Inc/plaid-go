package plaid

import (
	"encoding/json"
	"errors"
)

type AssetReport struct {
	AssetReportID  string            `json:"asset_report_id"`
	ClientReportID string            `json:"client_report_id"`
	DateGenerated  string            `json:"date_generated"`
	DaysRequested  int               `json:"days_requested"`
	Items          []AssetReportItem `json:"items"`
	User           AssetReportUser   `json:"user"`
}

type AssetReportItem struct {
	Accounts        []Account `json:"accounts"`
	DateLastUpdated string    `json:"date_last_updated"`
	InstitutionID   string    `json:"institution_id"`
	InstitutionName string    `json:"institution_name"`
	ItemID          string    `json:"item_id"`
}

type AssetReportUser struct {
	ClientID    string `json:"client_user_id"`
	Email       string `json:"email"`
	FirstName   string `json:"first_name"`
	LastName    string `json:"last_name"`
	MiddleName  string `json:"middle_name"`
	PhoneNumber string `json:"phone_number"`
	SSN         string `json:"ssn"`
}

type createAssetReportRequestOptions struct {
	ClientReportID string           `json:"client_report_id,omitempty"`
	Webhook        string           `json:"webhook,omitempty"`
	User           *AssetReportUser `json:"user,omitempty"`
}

type createAssetReportRequest struct {
	ClientID      string                          `json:"client_id"`
	Secret        string                          `json:"secret"`
	AccessTokens  []string                        `json:"access_tokens"`
	DaysRequested int                             `json:"days_requested"`
	Options       createAssetReportRequestOptions `json:"options,omitempty"`
}

type CreateAssetReportOptions struct {
	DaysRequested  int
	ClientReportID string
	Webhook        string
	User           *AssetReportUser
}

type CreateAssetReportResponse struct {
	APIResponse
	AssetReportToken string `json:"asset_report_token"`
	AssetReportID    string `json:"asset_report_id"`
}

type refreshAssetReportRequestOptions struct {
	ClientReportID string           `json:"client_report_id,omitempty"`
	Webhook        string           `json:"webhook,omitempty"`
	User           *AssetReportUser `json:"user,omitempty"`
}

type refreshAssetReportRequest struct {
	ClientID         string                           `json:"client_id"`
	Secret           string                           `json:"secret"`
	AssetReportToken string                           `json:"asset_report_token"`
	DaysRequested    int                              `json:"days_requested,omitempty"`
	Options          refreshAssetReportRequestOptions `json:"options,omitempty"`
}

type RefreshAssetReportResponse struct {
	APIResponse
	AssetReportToken string `json:"asset_report_token"`
	AssetReportID    string `json:"asset_report_id"`
}

type RefreshAssetReportOptions struct {
	DaysRequested  int
	ClientReportID string
	Webhook        string
	User           *AssetReportUser
}

type filterAssetReportRequest struct {
	ClientID            string   `json:"client_id"`
	Secret              string   `json:"secret"`
	AssetReportToken    string   `json:"asset_report_token"`
	AccountIDsToExclude []string `json:"account_ids_to_exclude"`
}

type FilterAssetReportResponse struct {
	APIResponse
	AssetReportToken string `json:"asset_report_token"`
	AssetReportID    string `json:"asset_report_id"`
}

type getAssetReportRequest struct {
	ClientID         string `json:"client_id"`
	Secret           string `json:"secret"`
	AssetReportToken string `json:"asset_report_token"`
}

type GetAssetReportResponse struct {
	APIResponse
	Report   AssetReport `json:"report"`
	Warnings []string    `json:"warnings"`
}

type removeAssetReportRequest struct {
	ClientID         string `json:"client_id"`
	Secret           string `json:"secret"`
	AssetReportToken string `json:"asset_report_token"`
}

type RemoveAssetReportResponse struct {
	APIResponse
	Removed bool `json:"removed"`
}

type createAuditCopyRequest struct {
	ClientID         string `json:"client_id"`
	Secret           string `json:"secret"`
	AssetReportToken string `json:"asset_report_token"`
	AuditorID        string `json:"auditor_id"`
}

type CreateAuditCopyTokenResponse struct {
	APIResponse
	AuditCopyToken string `json:"audit_copy_token"`
}

func (c *Client) CreateAssetReportWithOptions(accessTokens []string, options CreateAssetReportOptions) (resp CreateAssetReportResponse, err error) {
	req := createAssetReportRequest{
		ClientID:      c.clientID,
		Secret:        c.secret,
		AccessTokens:  accessTokens,
		DaysRequested: options.DaysRequested,
		Options: createAssetReportRequestOptions{
			ClientReportID: options.ClientReportID,
			Webhook:        options.Webhook,
			User:           options.User,
		},
	}

	jsonBody, err := json.Marshal(req)
	if err != nil {
		return resp, err
	}

	err = c.Call("/asset_report/create", jsonBody, &resp)
	return resp, err
}

func (c *Client) CreateAssetReport(accessTokens []string) (resp CreateAssetReportResponse, err error) {
	return c.CreateAssetReportWithOptions(accessTokens, CreateAssetReportOptions{
		DaysRequested: 30,
	})
}

func (c *Client) RefreshAssetReportWithOptions(assetReportToken string, options RefreshAssetReportOptions) (resp RefreshAssetReportResponse, err error) {
	req := refreshAssetReportRequest{
		ClientID:         c.clientID,
		Secret:           c.secret,
		AssetReportToken: assetReportToken,
		DaysRequested:    options.DaysRequested,
		Options: refreshAssetReportRequestOptions{
			ClientReportID: options.ClientReportID,
			Webhook:        options.Webhook,
			User:           options.User,
		},
	}

	jsonBody, err := json.Marshal(req)
	if err != nil {
		return resp, err
	}

	err = c.Call("/asset_report/refresh", jsonBody, &resp)
	return resp, err
}

func (c *Client) RefreshAssetReport(assetReportToken string) (resp RefreshAssetReportResponse, err error) {
	return c.RefreshAssetReportWithOptions(assetReportToken, RefreshAssetReportOptions{})
}

func (c *Client) FilterAssetReport(assetReportToken string, accountIDsToExclude []string) (resp FilterAssetReportResponse, err error) {
	req := filterAssetReportRequest{
		ClientID:            c.clientID,
		Secret:              c.secret,
		AssetReportToken:    assetReportToken,
		AccountIDsToExclude: accountIDsToExclude,
	}

	jsonBody, err := json.Marshal(req)
	if err != nil {
		return resp, err
	}

	err = c.Call("/asset_report/filter", jsonBody, &resp)
	return resp, err
}

func (c *Client) GetAssetReport(assetReportToken string) (resp GetAssetReportResponse, err error) {
	if assetReportToken == "" {
		return resp, errors.New("/asset_report/get - asset report token must be specified")
	}

	jsonBody, err := json.Marshal(getAssetReportRequest{
		ClientID:         c.clientID,
		Secret:           c.secret,
		AssetReportToken: assetReportToken,
	})

	if err != nil {
		return resp, err
	}

	err = c.Call("/asset_report/get", jsonBody, &resp)
	return resp, err
}

func (c *Client) CreateAuditCopy(assetReportToken, auditorID string) (resp CreateAuditCopyTokenResponse, err error) {
	if assetReportToken == "" || auditorID == "" {
		return resp, errors.New("/asset_report/audit_copy/create - asset report token and auditor id must be specified")
	}

	jsonBody, err := json.Marshal(createAuditCopyRequest{
		ClientID:         c.clientID,
		Secret:           c.secret,
		AssetReportToken: assetReportToken,
		AuditorID:        auditorID,
	})

	if err != nil {
		return resp, err
	}

	err = c.Call("/asset_report/audit_copy/create", jsonBody, &resp)
	return resp, err
}

func (c *Client) RemoveAssetReport(assetReportToken string) (resp RemoveAssetReportResponse, err error) {
	if assetReportToken == "" {
		return resp, errors.New("/asset_report/remove - asset report token must be specified")
	}

	jsonBody, err := json.Marshal(removeAssetReportRequest{
		ClientID:         c.clientID,
		Secret:           c.secret,
		AssetReportToken: assetReportToken,
	})

	if err != nil {
		return resp, err
	}

	err = c.Call("/asset_report/remove", jsonBody, &resp)
	return resp, err
}
