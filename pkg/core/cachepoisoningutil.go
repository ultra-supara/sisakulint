package core

import "gopkg.in/yaml.v3"

// RemoveRefFromWith removes the "ref" key from the "with" section of a YAML step node.
// This is used by cache poisoning rules to fix unsafe checkout refs.
func RemoveRefFromWith(stepNode *yaml.Node) error {
	for i := 0; i < len(stepNode.Content); i += 2 {
		if i+1 >= len(stepNode.Content) {
			break
		}
		key := stepNode.Content[i]
		val := stepNode.Content[i+1]

		if key.Value == "with" && val.Kind == yaml.MappingNode {
			newContent := make([]*yaml.Node, 0, len(val.Content))
			for j := 0; j < len(val.Content); j += 2 {
				if j+1 >= len(val.Content) {
					break
				}
				withKey := val.Content[j]
				if withKey.Value != "ref" {
					newContent = append(newContent, val.Content[j], val.Content[j+1])
				}
			}
			if len(newContent) == 0 {
				stepNode.Content = append(stepNode.Content[:i], stepNode.Content[i+2:]...)
			} else {
				val.Content = newContent
			}
			return nil
		}
	}
	return nil
}
