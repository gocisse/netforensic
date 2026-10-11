package analyzer

import "github.com/gocisse/netforensic/internal/models"

// Flow statuses.
const (
	statusWorking = "working"
	statusSlow    = "slow"
	statusBroken  = "broken"

	// slowRTTMs is the average round trip above which a flow counts as slow.
	slowRTTMs = 200.0
)

// annotateFlowStatus sets the Status and IssueCount of every flow from the
// issues that name it and from its own timings.
func annotateFlowStatus(flows []models.Flow, issues []models.Issue) {
	type tally struct {
		count int
		worst models.Severity
	}
	byFlow := make(map[string]*tally)
	for _, is := range issues {
		if is.Category == "Capture" {
			continue
		}
		for _, id := range flowIDs(is) {
			t := byFlow[id]
			if t == nil {
				t = &tally{}
				byFlow[id] = t
			}
			t.count++
			if t.worst == "" || severityRank(is.Severity) > severityRank(t.worst) {
				t.worst = is.Severity
			}
		}
	}
	for i := range flows {
		f := &flows[i]
		f.Status = statusWorking
		t := byFlow[f.ID]
		if t != nil {
			f.IssueCount = t.count
			if severityRank(t.worst) >= severityRank(models.SeverityError) {
				f.Status = statusBroken
				continue
			}
			if severityRank(t.worst) >= severityRank(models.SeverityWarning) {
				f.Status = statusSlow
			}
		}
		if f.Retransmits > 0 || f.SetupTimeMs > slowSetupMs || f.TTFBMs > slowTTFBMs || f.AvgRTTMs > slowRTTMs {
			f.Status = statusSlow
		}
	}
}
