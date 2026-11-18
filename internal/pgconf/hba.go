package pgconf

import (
	"fmt"
	"net/netip"
)

// HBA renders pg_hba.conf for a project whose network is slice, an IPv4 /26
// (host bits are masked off): the platform's superuser over the socket by SCRAM
// only, the backup role over the socket by peer only, every other role by SCRAM
// from loopback and the slice, nothing else.
func HBA(slice netip.Prefix) ([]byte, error) {
	if !slice.IsValid() || !slice.Addr().Is4() || slice.Addr().IsUnspecified() || slice.Bits() != 26 {
		return nil, fmt.Errorf("pgconf: project slice %s is not an IPv4 /26", slice)
	}
	return fmt.Appendf(nil, `local   all  supabase_admin                 scram-sha-256
local   all  supapace_backup                peer map=supapace
local   all  all                            reject
host    all  supabase_admin   all           reject
host    all  supapace_backup  all           reject
host    all  all              127.0.0.1/32  scram-sha-256
host    all  all              ::1/128       scram-sha-256
host    all  all              %s/26    scram-sha-256
host    all  all              0.0.0.0/0     reject
host    all  all              ::/0          reject
`, slice.Masked().Addr()), nil
}

// Ident renders pg_ident.conf: the container's postgres user (the project uid)
// may log in as the backup role.
func Ident() []byte {
	return []byte("supapace  postgres  supapace_backup\n")
}
