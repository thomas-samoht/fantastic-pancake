package example.authz

default allow := false

allow if {
	input.message == "noodgeval"
}

allow if {
	some i, j
	data.authz.users[i].name == input.user
	some k in data.authz.users[i].authorized_orgs
	k == data.authz.organizations[j].ura
	data.authz.organizations[j].ura == input.organization
}
