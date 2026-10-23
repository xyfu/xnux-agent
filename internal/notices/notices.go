// Package notices holds xnux-agent's licence and the third-party notices
// for what its binary links (thread 0045), so they travel with it:
// `xnux-agent license` and `xnux-agent notices` print them, and install.sh
// writes them to /usr/share/doc/xnux-agent. scripts/notices keeps both
// files in step with LICENSE and the dependencies.
package notices

import _ "embed"

// License is the agent's own licence (Apache-2.0).
//
//go:embed LICENSE
var License string

// ThirdParty is THIRD_PARTY_NOTICES.
//
//go:embed THIRD_PARTY_NOTICES
var ThirdParty string
