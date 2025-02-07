package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
)

func main() {
	// Load global data from JSON file
	data, err := loadJSONFile("./opa_data/data.json")
	if err != nil {
		fmt.Println("Error loading data:", err)
		return
	}

	// Load per-query input data from JSON file
	input, err := loadJSONFile("./opa_data/input_1.json")
	if err != nil {
		fmt.Println("Error loading input:", err)
		return
	}

	// Store the global data in OPA’s in-memory store
	store := inmem.NewFromObject(data)

	// Define a Rego query that uses both `data` and `input`
	query := rego.New(
		rego.Query("data.example.authz"),
		rego.Module("policy.rego", `
			package example.authz

			default allow := false

			allow if {
					input.message == "noodgeval"
			}

			allow if {
					some i, j
					data.users[i].name == input.user
					some k in data.users[i].authorized_orgs
					k == data.organizations[j].ura
					data.organizations[j].ura == input.organization
			}
		`),
		rego.Store(store), // Attach global data
		rego.Input(input), // Attach dynamic input
	)

	// Evaluate the query
	rs, err := query.Eval(context.Background())
	if err != nil {
		fmt.Println("Error evaluating policy:", err)
		return
	}

	// Print result
	fmt.Println("Policy Result:", rs)
}

// loadJSONFile reads a JSON file and unmarshals it into a map
func loadJSONFile(filename string) (map[string]interface{}, error) {
	file, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var data map[string]interface{}
	if err := json.Unmarshal(file, &data); err != nil {
		return nil, err
	}

	return data, nil
}
