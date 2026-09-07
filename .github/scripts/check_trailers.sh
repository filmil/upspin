#!/bin/bash
# Checks that every commit made by an assistant in a range carries the
# trailers the SOP (github.com/filmil/ai-coding-sop, git-commit-rules)
# requires. A commit counts as an assistant commit when its message holds
# the attribution note. Such a commit must also hold the prompt that made
# it, introduced by a line that starts with "Prompt" ("Prompt:",
# "Prompts:", "Prompts, in full and in order:"). Other commits pass.
# The Co-Authored-By trailer that Claude Code adds is not required: the
# SOP does not ask for it, and assistant commits from other tools do not
# carry it.
#
# Arguments:
#   $1  A git revision range, for example origin/main..HEAD.
#
# Exit status:
#   0  every assistant commit in the range has the trailers
#   1  at least one does not; each is named on stderr
#   2  the range is missing or not valid
set -u
range=${1:-}
if [[ -z "$range" ]]; then
	echo "usage: $0 <revision-range>" >&2
	exit 2
fi
commits=$(git rev-list "$range" 2>/dev/null) || {
	echo "check_trailers: not a valid range: $range" >&2
	exit 2
}
status=0
for c in $commits; do
	msg=$(git log -1 --format=%B "$c")
	if ! grep -q "created by an automated coding assistant" <<<"$msg"; then
		continue
	fi
	if ! grep -qE '^Prompts?\b' <<<"$msg"; then
		echo "check_trailers: $(git log -1 --format='%h %s' "$c") is an assistant commit without its prompt" >&2
		status=1
	fi
done
exit $status
