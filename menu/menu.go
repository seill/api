package menu

import "strings"

var Items []Item

type Item struct {
	Title    string  `json:"title"`
	Icon     *string `json:"icon"`
	Link     *string `json:"link"`
	Home     *bool   `json:"home"`
	Group    *bool   `json:"group"`
	Resource *string `json:"resource"`
	Children []Item  `json:"children"`
}

func GetItems(resources []string) (items []Item) {
	items = getItems(resources, Items)

	return
}

func getItems(resources []string, originalItems []Item) (items []Item) {
	items = []Item{}

	for _, item := range originalItems {
		for _, resource := range resources {
			if nil == item.Resource || 0 == strings.Compare(resource, "*") || 0 == strings.Compare(resource, *item.Resource) {
				if nil != item.Children {
					childrenItems := getItems(resources, item.Children)
					item.Children = childrenItems
				}

				items = append(items, item)
				break
			}
		}
	}

	return
}
