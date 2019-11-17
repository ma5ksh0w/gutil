package bhx

import "testing"

func TestAccounts(t *testing.T) {
	acc1, err := MakeNewAccount("tester1")
	if err != nil {
		t.Fatal(err)
	}

	acc1.Fields["key1"] = "val1"
	acc1.Fields["key2"] = "val2"

	acc2, err := MakeNewAccount("tester2")
	if err != nil {
		t.Fatal(err)
	}

	acc2.Fields["example-meta-key"] = "1"

	pac1 := acc1.GetAccount()
	if !pac1.Verify() {
		t.Fatal("verification failed")
	}

	raw, err := pac1.ExportJSON()
	if err != nil {
		t.Fatal(err)
	}

	Logf("Public account 1: %s", raw)

	raw2, err := acc2.ExportJSON("testpass")
	if err != nil {
		t.Fatal(err)
	}

	Logf("Raw private account 2: %s", raw2)

	acc3, err := new(MyAccount).ImportJSON(raw2, "testpass")
	if err != nil {
		t.Fatal(err)
	}

	Logf("-- decode ok, %+v", acc3)
}
