package planner

import "fmt"

// ValidatePlan rejects malformed task graphs before the executor can deadlock
// or silently skip work.
func ValidatePlan(plan *Plan) error {
	if plan == nil {
		return fmt.Errorf("plan is nil")
	}
	if len(plan.Tasks) == 0 {
		return fmt.Errorf("plan contains no tasks")
	}
	byID := make(map[string]*TaskNode, len(plan.Tasks))
	for _, task := range plan.Tasks {
		if task == nil || task.ID == "" {
			return fmt.Errorf("plan contains a task without an ID")
		}
		if _, exists := byID[task.ID]; exists {
			return fmt.Errorf("plan contains duplicate task ID %q", task.ID)
		}
		byID[task.ID] = task
	}
	for _, task := range plan.Tasks {
		for _, dependency := range task.DependsOn {
			if _, ok := byID[dependency]; !ok {
				return fmt.Errorf("task %q depends on unknown task %q", task.ID, dependency)
			}
		}
	}

	state := make(map[string]uint8, len(byID))
	var visit func(string) error
	visit = func(id string) error {
		switch state[id] {
		case 1:
			return fmt.Errorf("plan contains a dependency cycle at task %q", id)
		case 2:
			return nil
		}
		state[id] = 1
		for _, dependency := range byID[id].DependsOn {
			if err := visit(dependency); err != nil {
				return err
			}
		}
		state[id] = 2
		return nil
	}
	for id := range byID {
		if err := visit(id); err != nil {
			return err
		}
	}
	return nil
}
