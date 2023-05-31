package hellosign

import (
	"context"
	"log"
	"net/http"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/dnaeon/go-vcr.v3/cassette"
	"gopkg.in/dnaeon/go-vcr.v3/recorder"
)

func TestCreateEmbeddedSignatureRequestSuccess(t *testing.T) {
	// Start our recorder
	vcr := fixture("fixtures/embedded_signature_request")
	defer vcr.Stop() // Make sure recorder is stopped once done with it

	client := createVcrClient(vcr)

	embReq := creationRequest()
	res, err := client.CreateEmbeddedSignatureRequest(context.Background(), embReq)

	assert.NotNil(t, res, "Should return response")
	assert.Nil(t, err, "Should not return error")

	assert.Equal(t, "770e57f4c3480945ee850633daf903ed69b9eca9", res.SignatureRequestID)
	assert.Equal(t, "awesome", res.Subject)
	assert.Equal(t, true, res.TestMode)
	assert.Equal(t, false, res.IsComplete)
	assert.Equal(t, false, res.IsDeclined)
}

func TestCreateEmbeddedSignatureRequestSuccess2(t *testing.T) {
	// Start our recorder
	vcr := fixture("fixtures/embedded_signature_request_more_fields")
	defer vcr.Stop() // Make sure recorder is stopped once done with it

	client := createVcrClient(vcr)

	embReq := creationRequest()
	res, err := client.CreateEmbeddedSignatureRequest(context.Background(), embReq)

	assert.NotNil(t, res, "Should return response")
	assert.Nil(t, err, "Should not return error")

	assert.Equal(t, "ea8e2061af75a2fc3a8c440420cee674481cec40", res.SignatureRequestID)
	assert.Equal(t, "awesome", res.Subject)
	assert.Equal(t, true, res.TestMode)
	assert.Equal(t, false, res.IsComplete)
	assert.Equal(t, false, res.IsDeclined)
}

func TestCreateEmbeddedSignatureRequestMissingSigners(t *testing.T) {
	// Start our recorder
	vcr := fixture("fixtures/embedded_signature_request_missing_signers")
	defer vcr.Stop() // Make sure recorder is stopped once done with it

	client := createVcrClient(vcr)

	embReq := creationRequest()
	embReq.Signers = []Signer{}

	res, err := client.CreateEmbeddedSignatureRequest(context.Background(), embReq)

	assert.Nil(t, res, "Should not return response")
	assert.NotNil(t, err, "Should return error")

	assert.Equal(t, err.Error(), "bad_request: Cannot specify form_fields_per_document unless you also specify signers")
}
func TestCreateEmbeddedSignatureRequestWarnings(t *testing.T) {
	// Start our recorder
	vcr := fixture("fixtures/embedded_signature_request_warnings")
	defer vcr.Stop() // Make sure recorder is stopped once done with it

	client := createVcrClient(vcr)

	embReq := creationRequest()
	embReq.Signers = []Signer{}
	embReq.FormFieldsPerDocument = [][]DocumentFormField{}
	res, err := client.CreateEmbeddedSignatureRequest(context.Background(), embReq)

	assert.Nil(t, res, "Should not return response")
	assert.NotNil(t, err, "Should return error")

	assert.Equal(t, err.Error(), "bad_request: Must specify a name for each signer")
}

func TestCreateEmbeddedSignatureRequestFileURL(t *testing.T) {
	// Start our recorder
	vcr := fixture("fixtures/embedded_signature_request_file_url")
	defer vcr.Stop() // Make sure recorder is stopped once done with it

	client := createVcrClient(vcr)

	request := CreationRequest{
		TestMode: true,
		ClientID: os.Getenv("HELLOSIGN_CLIENT_ID"),
		FileURL:  []string{"http://www.pdf995.com/samples/pdf.pdf"},
		Title:    "My First Document",
		Subject:  "Contract",
		Signers: []Signer{
			{
				Email: "jane@example.com",
				Name:  "Jane Doe",
			},
		},
	}

	res, err := client.CreateEmbeddedSignatureRequest(context.Background(), request)
	assert.NotNil(t, res, "Should return response")
	assert.Nil(t, err, "Should not return error")

	assert.Equal(t, "51ef2d13f9172c23a7d4a1b8bf83d0200ef12dbc", res.SignatureRequestID)
	assert.Equal(t, "My First Document", res.Title)
	assert.Equal(t, true, res.TestMode)
	assert.Equal(t, false, res.IsComplete)
	assert.Equal(t, false, res.IsDeclined)
}

func TestGetSignatureRequest(t *testing.T) {
	vcr := fixture("fixtures/get_signature_request")
	defer vcr.Stop() // Make sure recorder is stopped once done with it

	client := createVcrClient(vcr)

	res, err := client.GetSignatureRequest(context.Background(), "770e57f4c3480945ee850633daf903ed69b9eca9")

	assert.NotNil(t, res, "Should return response")
	assert.Nil(t, err, "Should not return error")

	assert.Equal(t, "770e57f4c3480945ee850633daf903ed69b9eca9", res.SignatureRequestID)
	assert.Equal(t, "awesome", res.Subject)
	assert.Equal(t, true, res.TestMode)
	assert.Equal(t, false, res.IsComplete)
	assert.Equal(t, false, res.IsDeclined)
}

func TestListSignatureRequests(t *testing.T) {
	vcr := fixture("fixtures/list_signature_requests")
	defer vcr.Stop() // Make sure recorder is stopped once done with it

	client := createVcrClient(vcr)

	res, err := client.ListSignatureRequests(context.Background())

	assert.NotNil(t, res, "Should return response")
	assert.Nil(t, err, "Should not return error")

	assert.Equal(t, 9937, res.ListInfo.NumPages)
	assert.Equal(t, 1, res.ListInfo.Page)
	assert.Equal(t, 198731, res.ListInfo.NumResults)
	assert.Equal(t, 20, res.ListInfo.PageSize)

	assert.Equal(t, 20, len(res.SignatureRequests))
}

func TestGetEmbeddedSignURL(t *testing.T) {
	vcr := fixture("fixtures/get_embedded_sign_url")
	defer vcr.Stop() // Make sure recorder is stopped once done with it

	client := createVcrClient(vcr)

	res, err := client.GetEmbeddedSignURL(context.Background(), "deaf86bfb33764d9a215a07cc060122d")

	assert.NotNil(t, res, "Should return response")
	assert.Nil(t, err, "Should not return error")

	assert.Contains(t, res.SignURL, "embeddedSign?signature_id=deaf86bfb33764d9a215a07cc060122d&token=")
	assert.Equal(t, 1685479225, res.ExpiresAt)
}

func TestSaveFile(t *testing.T) {
	vcr := fixture("fixtures/get_pdf")
	defer vcr.Stop() // Make sure recorder is stopped once done with it

	client := createVcrClient(vcr)

	fileInfo, err := client.SaveFile(context.Background(), "6d7ad140141a7fe6874fec55931c363e0301c353", "pdf", "/tmp/download.pdf")

	assert.NotNil(t, fileInfo, "Should return response")
	assert.Nil(t, err, "Should not return error")

	assert.Equal(t, int64(98781), fileInfo.Size())
	assert.Equal(t, "download.pdf", fileInfo.Name())
}

func TestGetPDF(t *testing.T) {
	vcr := fixture("fixtures/get_pdf")
	defer vcr.Stop() // Make sure recorder is stopped once done with it

	client := createVcrClient(vcr)

	data, err := client.GetPDF(context.Background(), "6d7ad140141a7fe6874fec55931c363e0301c353")

	assert.NotNil(t, data, "Should return response")
	assert.Nil(t, err, "Should not return error")

	assert.Equal(t, 98781, len(data))
}

func TestGetFilesAsDataURI(t *testing.T) {
	vcr := fixture("fixtures/get_files_as_data_uri")
	defer vcr.Stop() // Make sure recorder is stopped once done with it

	client := createVcrClient(vcr)

	response, err := client.GetFilesAsDataURI(context.Background(), "6d7ad140141a7fe6874fec55931c363e0301c353")

	assert.NotNil(t, response, "Should return response")
	assert.Nil(t, err, "Should not return error")

	assert.Equal(t, 131737, len(response.DataUri))
}

func TestGetFilesAsFileURL(t *testing.T) {
	vcr := fixture("fixtures/get_files_as_file_url")
	defer vcr.Stop() // Make sure recorder is stopped once done with it

	client := createVcrClient(vcr)

	response, err := client.GetFilesAsFileURL(context.Background(), "6d7ad140141a7fe6874fec55931c363e0301c353")

	assert.NotNil(t, response, "Should return response")
	assert.Nil(t, err, "Should not return error")

	assert.Contains(t, response.FileUrl, "https://s3.amazonaws.com/hellofax_uploads/super_groups/2017/09/12/6d7ad140141a7fe6874fec55931c363e0301c353/merged-initial.pdf")
	assert.Equal(t, 1685810514, response.ExpiresAt)
}

func TestCreateSignatureRequestSuccess(t *testing.T) {
	// Start our recorder
	vcr := fixture("fixtures/create_signature_request")
	defer vcr.Stop() // Make sure recorder is stopped once done with it

	client := createVcrClient(vcr)

	embReq := creationRequest()
	res, err := client.CreateSignatureRequest(context.Background(), embReq)

	assert.NotNil(t, res, "Should return response")
	assert.Nil(t, err, "Should not return error")

	assert.Equal(t, "4326c7f17970b98aefef0bffc8b692c11244c256", res.SignatureRequestID)
	assert.Equal(t, "awesome", res.Subject)
	assert.Equal(t, true, res.TestMode)
	assert.Equal(t, false, res.IsComplete)
	assert.Equal(t, false, res.IsDeclined)
}

func TestCancelSignatureRequests(t *testing.T) {
	vcr := fixture("fixtures/cancel_signature_request")
	defer vcr.Stop() // Make sure recorder is stopped once done with it

	client := createVcrClient(vcr)

	res, err := client.CancelSignatureRequest(context.Background(), "d14084ca3136ab38d34623b13fb9839fdb6526e2")

	assert.NotNil(t, res, "Should return response")
	assert.Nil(t, err, "Should not return error")

	assert.Equal(t, 200, res.StatusCode)
}

func TestRemoveSignatureRequestsAccess(t *testing.T) {
	vcr := fixture("fixtures/remove_signature_request_access")
	defer vcr.Stop() // Make sure recorder is stopped once done with it

	client := createVcrClient(vcr)

	res, err := client.RemoveSignatureRequestAccess(context.Background(), "becc4e1182869bca15edb4ff494ab339bdd22652")

	assert.NotNil(t, res, "Should return response")
	assert.Nil(t, err, "Should not return error")

	assert.Equal(t, 400, res.StatusCode)
}

func TestUpdateSignatureRequestSuccess(t *testing.T) {
	vcr := fixture("fixtures/update_signature_request")
	defer vcr.Stop() // Make sure recorder is stopped once done with it

	client := createVcrClient(vcr)

	res, err := client.UpdateSignatureRequest(
		context.Background(),
		"9040be434b1301e31019b3dad895ed580f8ca890",
		"deaf86bfb33764d9a215a07cc060122d",
		"franky1@hellosign.com",
	)

	assert.Nil(t, err, "Should not return error")
	assert.NotNil(t, res, "Should return response")

	assert.Equal(t, "9040be434b1301e31019b3dad895ed580f8ca890", res.SignatureRequestID)
	assert.Equal(t, "franky1@hellosign.com", res.Signatures[0].SignerEmailAddress)
}

func TestUpdateSignatureRequestFails(t *testing.T) {
	vcr := fixture("fixtures/update_signature_request_deleted")
	defer vcr.Stop() // Make sure recorder is stopped once done with it

	client := createVcrClient(vcr)

	res, err := client.UpdateSignatureRequest(
		context.Background(),
		"5c002b65dfefab79795a521bef312c45914cc48d",
		"d82212e10dcf71ad465e033907074423",
		"franky@hellosign.com",
	)

	assert.Nil(t, res, "Should not return response")
	assert.NotNil(t, err, "Should return error")

	assert.Equal(t, "deleted: This resource has been deleted", err.Error())
}

func TestClient_WithHTTPClient(t *testing.T) {
	assert := assert.New(t)

	client := &Client{}

	defaultHTTPClient := client.getHTTPClient()

	customHTTPClient := &http.Client{Transport: http.DefaultTransport}
	client.WithHTTPClient(customHTTPClient)

	assert.NotEqual(defaultHTTPClient, client.getHTTPClient())
	assert.Equal(customHTTPClient, client.getHTTPClient())
}

// Private Functions

func fixture(path string) *recorder.Recorder {
	vcr, err := recorder.New(path)
	if err != nil {
		log.Fatal(err)
	}

	// Add a hook which removes Authorization headers from all requests
	hook := func(i *cassette.Interaction) error {
		delete(i.Request.Headers, "Authorization")
		return nil
	}
	vcr.AddHook(hook, recorder.AfterCaptureHook)

	return vcr
}

func createVcrClient(transport *recorder.Recorder) Client {
	httpClient := &http.Client{Transport: transport}

	client := Client{
		APIKey:     os.Getenv("HELLOSIGN_API_KEY"),
		HTTPClient: httpClient,
	}
	return client
}

func creationRequest() CreationRequest {

	return CreationRequest{
		TestMode: true,
		ClientID: os.Getenv("HELLOSIGN_CLIENT_ID"),
		File: []string{
			"fixtures/offer_letter.pdf",
			"fixtures/offer_letter.pdf",
		},
		Title:   "cool title",
		Subject: "awesome",
		Message: "cool message bro",
		// SigningRedirectURL: "example signing redirect url",
		Signers: []Signer{
			{
				Email: "freddy@hellosign.com",
				Name:  "Freddy Rangel",
			},
			{
				Email: "frederick.rangel@gmail.com",
				Name:  "Frederick Rangel",
			},
		},
		CCEmailAddresses: []string{
			"no@cats.com",
			"no@dogs.com",
		},
		UseTextTags:  false,
		HideTextTags: true,
		Metadata: map[string]string{
			"no":   "cats",
			"more": "dogs",
		},
		FormFieldsPerDocument: [][]DocumentFormField{
			[]DocumentFormField{
				{
					APIId:    "api_id",
					Name:     "display name",
					Type:     "text",
					X:        123,
					Y:        456,
					Width:    678,
					Required: true,
					Signer:   0,
				},
			},
			[]DocumentFormField{
				{
					APIId:    "api_id_2",
					Name:     "display name 2",
					Type:     "text",
					X:        123,
					Y:        456,
					Width:    678,
					Required: true,
					Signer:   1,
				},
			},
		},
	}
}
