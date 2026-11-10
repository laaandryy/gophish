package models

import (
	check "gopkg.in/check.v1"
)

func (s *ModelsSuite) TestPostIMAP(c *check.C) {
	im := IMAP{
		UserId:   1,
		Enabled:  true,
		Host:     "127.0.0.1",
		Port:     993,
		Username: "user",
		Password: "password",
		TLS:      true,
	}
	c.Assert(PostIMAP(&im, 1), check.Equals, nil)

	// Saving the settings again replaces the previous ones
	im.Host = "127.0.0.2"
	c.Assert(PostIMAP(&im, 1), check.Equals, nil)
	ims, err := GetIMAP(1)
	c.Assert(err, check.Equals, nil)
	c.Assert(ims, check.HasLen, 1)
	c.Assert(ims[0].Host, check.Equals, "127.0.0.2")
	c.Assert(ims[0].LastLogin.IsZero(), check.Equals, true)

	c.Assert(SuccessfulLogin(&ims[0]), check.Equals, nil)
	ims, err = GetIMAP(1)
	c.Assert(err, check.Equals, nil)
	c.Assert(ims[0].LastLogin.IsZero(), check.Equals, false)

	c.Assert(DeleteIMAP(1), check.Equals, nil)
	ims, err = GetIMAP(1)
	c.Assert(err, check.Equals, nil)
	c.Assert(ims, check.HasLen, 0)
}
