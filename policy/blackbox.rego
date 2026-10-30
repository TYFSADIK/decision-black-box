package blackbox

import rego.v1

# Decision document: {"allow": bool, "deny": [reasons]}
default decision := {"allow": false, "deny": ["no rule matched"]}

decision := {"allow": count(deny) == 0, "deny": deny}

deny contains "operator not authorised for this action" if {
	not input.action in data.roles[input.actor_role]
}

deny contains "high-impact action requires a second operator" if {
	input.action in {"track.designate_hostile", "asset.task"}
	not input.second_operator
}

deny contains "track confidence below threshold for classification" if {
	input.action == "track.classify"
	input.track.confidence < 0.6
}

deny contains "decision made on stale data" if {
	input.track.age_s > 10
}
