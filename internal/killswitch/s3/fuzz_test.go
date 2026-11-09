package s3

import "testing"

// parseListVersions на произвольном вводе не паникует; ошибка всегда класса parse.
func FuzzParseListVersions(f *testing.F) {
	f.Add([]byte(`<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><IsTruncated>true</IsTruncated><NextKeyMarker>k</NextKeyMarker><NextVersionIdMarker>v</NextVersionIdMarker><Version><Key>a</Key><VersionId>1</VersionId><IsLatest>true</IsLatest></Version><DeleteMarker><Key>b</Key><VersionId>2</VersionId></DeleteMarker></ListVersionsResult>`))
	f.Add([]byte(``))
	f.Add([]byte(`<ListVersionsResult><Version><Key></Key></Version>`))
	f.Add([]byte(`<<<`))
	f.Fuzz(func(t *testing.T, in []byte) {
		r, err := parseListVersions(in)
		if err != nil {
			if e, ok := err.(*Error); !ok || e.Kind != "parse" {
				t.Fatalf("неожиданная ошибка: %v", err)
			}
			if len(r.Versions) != 0 || len(r.DeleteMarkers) != 0 {
				t.Fatal("при ошибке возвращены данные")
			}
		}
	})
}
