package core

import (
	"github.com/haya14busa/go-sarif/sarif"
)

func toResult(fields *TemplateFields) sarif.Result {
	return sarif.Result{
		RuleID: sarif.String(fields.Type),
		Level:  sarif.Warning.Ptr(),
		Message: sarif.Message{
			Text: &fields.Message,
		},
		Locations: []sarif.Location{
			{
				PhysicalLocation: &sarif.PhysicalLocation{
					Region: &sarif.Region{
						StartLine:   sarif.Int64(int64(fields.Line)),
						StartColumn: sarif.Int64(int64(fields.Column)),
						Snippet: &sarif.ArtifactContent{
							Text: &fields.Snippet,
						},
					},
				},
			},
		},
	}
}

func toSARIF(fields []*TemplateFields) (string, error) {
	s := &sarif.Sarif{
		Version: sarif.The210,
		Schema:  sarif.String("https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.4.json"),
		Runs: []sarif.Run{
			{
				Tool: sarif.Tool{
					Driver: sarif.ToolComponent{
						Name: "sisakulint",
					},
				},
			},
		},
	}
	for _, f := range fields {
		s.Runs[0].Results = append(s.Runs[0].Results, toResult(f))
	}
	json, err := s.Marshal()
	if err != nil {
		return "", err
	}
	return string(json), nil
}
