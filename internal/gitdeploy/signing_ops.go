package gitdeploy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/kylebegeman/helios/internal/kernel"
	"github.com/kylebegeman/helios/internal/state"
)

// The operations that change the signing policy. Each is planned, applied
// and recorded like any other change to the machine, so a person sees
// whose key is allowed before it is, and the history says who asked.
// Each plans its change from its input alone, and says in its note when
// the policy already has it: a daemon that stops after the policy is
// written plans the same change again as it resumes, and finishes.
const (
	SignersAddKind    = "git.signers.add"
	SignersRemoveKind = "git.signers.remove"
	RequireSignedKind = "git.signed.require"
)

// policyTarget is what the signers operations change, for their receipts.
const policyTarget = "git signers"

// SignersAdd is the Definition for SignersAddKind.
type SignersAdd struct {
	// Dir holds the signing policy; empty means SigningDir.
	Dir string
}

// SignersAddInput says who may sign, and with which public key.
type SignersAddInput struct {
	Principal string `json:"principal"`
	Key       string `json:"key"`
	// By is who asked, as the CLI found them.
	By string `json:"by,omitempty"`
}

// Kind implements kernel.Definition.
func (SignersAdd) Kind() string { return SignersAddKind }

// Plan implements kernel.Definition.
func (d SignersAdd) Plan(ctx context.Context, raw json.RawMessage) (*kernel.Plan, error) {
	var in SignersAddInput
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, fmt.Errorf("signers add input: %w", err)
	}
	if !ValidPrincipal(in.Principal) {
		return nil, errors.New("a signer's name is one word, such as an email address: letters, digits and . _ % + @ -, at most 100 characters")
	}
	k, err := ParseKey(in.Key)
	if err != nil {
		return nil, err
	}
	dir := policyDir(d.Dir)
	p, err := ReadPolicy(dir)
	if err != nil {
		return nil, err
	}
	holder := p.Holder(k.Blob, in.Principal)
	if holder != "" && holder != in.Principal {
		return nil, fmt.Errorf("key %s already signs as %s; helios git signers remove %s first", k.Fingerprint(), holder, k.Fingerprint())
	}
	change := fmt.Sprintf("let %s sign deploy commits with %s key %s", in.Principal, k.Type, k.Fingerprint())
	if in.By != "" {
		change += ", asked by " + in.By
	}
	note := "no app deploys only signed commits yet; helios git require-signed <app> makes one"
	if len(p.RequireSigned) > 0 {
		note = "deploys only signed commits: " + strings.Join(p.RequireSigned, ", ")
	}
	if holder == in.Principal {
		note = in.Principal + " already signs with this key, so nothing changes"
	}
	signer := Signer{Principal: in.Principal, Options: gitOnly, Type: k.Type, Blob: k.Blob}
	return &kernel.Plan{Target: policyTarget, Recovery: kernel.Resume, Steps: []kernel.Step{{
		Name: "allow signer", Change: change, Note: note,
		Apply: func(ctx context.Context, out io.Writer) error {
			err := UpdatePolicy(dir, func(p *Policy) error {
				switch holder := p.Holder(signer.Blob, signer.Principal); holder {
				case signer.Principal:
					return nil
				case "":
					p.Signers = append(p.Signers, signer)
					return nil
				default:
					return fmt.Errorf("key %s was allowed for %s since this was planned; plan again", signer.Fingerprint(), holder)
				}
			})
			if err != nil {
				return policyWriteError(err)
			}
			fmt.Fprintf(out, "%s may sign deploy commits with %s\n", signer.Principal, signer.Fingerprint())
			return nil
		},
	}}}, nil
}

// SignersRemove is the Definition for SignersRemoveKind.
type SignersRemove struct {
	// Dir holds the signing policy; empty means SigningDir.
	Dir string
}

// SignersRemoveInput names the signers to remove: by principal, SHA256:
// fingerprint, or public key.
type SignersRemoveInput struct {
	Signer string `json:"signer"`
	By     string `json:"by,omitempty"`
}

// Kind implements kernel.Definition.
func (SignersRemove) Kind() string { return SignersRemoveKind }

// Plan implements kernel.Definition.
func (d SignersRemove) Plan(ctx context.Context, raw json.RawMessage) (*kernel.Plan, error) {
	var in SignersRemoveInput
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, fmt.Errorf("signers remove input: %w", err)
	}
	which := strings.TrimSpace(in.Signer)
	if which == "" {
		return nil, errors.New("which signer? name one by principal, SHA256: fingerprint or public key")
	}
	who := which
	if strings.Contains(which, " ") {
		k, err := ParseKey(which)
		if err != nil {
			return nil, err
		}
		who = "the " + k.Type + " key " + k.Fingerprint()
	} else if strings.HasPrefix(which, "SHA256:") {
		who = "the key " + which
	}
	dir := policyDir(d.Dir)
	p, err := ReadPolicy(dir)
	if err != nil {
		return nil, err
	}
	change := "stop letting " + who + " sign deploy commits"
	if in.By != "" {
		change += ", asked by " + in.By
	}
	found := p.Remove(which)
	var note string
	if len(found) == 0 {
		note = "no allowed signer is " + which + " now, so nothing changes; helios git signers list shows them"
	} else {
		var gone []string
		for _, s := range found {
			gone = append(gone, s.Principal+" with "+s.Type+" key "+s.Fingerprint())
		}
		note = "removes " + strings.Join(gone, " and ")
		if len(p.Signers) == 0 && len(p.Others) == 0 && len(p.RequireSigned) > 0 {
			note += "; no signer is left after this, so every push of " + strings.Join(p.RequireSigned, ", ") + " is refused until one is added"
		}
	}
	return &kernel.Plan{Target: policyTarget, Recovery: kernel.Resume, Steps: []kernel.Step{{
		Name: "remove signer", Change: change, Note: note,
		Apply: func(ctx context.Context, out io.Writer) error {
			var removed []Signer
			if err := UpdatePolicy(dir, func(p *Policy) error { removed = p.Remove(which); return nil }); err != nil {
				return policyWriteError(err)
			}
			if len(removed) == 0 {
				fmt.Fprintf(out, "no allowed signer is %s\n", which)
			}
			for _, s := range removed {
				fmt.Fprintf(out, "removed %s with %s\n", s.Principal, s.Fingerprint())
			}
			return nil
		},
	}}}, nil
}

// RequireSigned is the Definition for RequireSignedKind.
type RequireSigned struct {
	Store *state.Store
	// Dir holds the signing policy; empty means SigningDir.
	Dir string
}

// RequireSignedInput says which app deploys only signed commits, or, with
// Off, deploys any commit again.
type RequireSignedInput struct {
	App string `json:"app"`
	Off bool   `json:"off,omitempty"`
	By  string `json:"by,omitempty"`
}

// Kind implements kernel.Definition.
func (RequireSigned) Kind() string { return RequireSignedKind }

// Plan implements kernel.Definition.
func (d RequireSigned) Plan(ctx context.Context, raw json.RawMessage) (*kernel.Plan, error) {
	var in RequireSignedInput
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, fmt.Errorf("require signed input: %w", err)
	}
	if !ValidApp(in.App) {
		return nil, errors.New("invalid app name")
	}
	dir := policyDir(d.Dir)
	p, err := ReadPolicy(dir)
	if err != nil {
		return nil, err
	}
	var change, note string
	if in.Off {
		change = fmt.Sprintf("deploy %s from any commit again, signed or not", in.App)
		if !p.Requires(in.App) {
			note = in.App + " doesn't require signed commits, so nothing changes"
		}
	} else {
		if len(p.Signers) == 0 && len(p.Others) == 0 {
			return nil, fmt.Errorf("no signer is allowed yet, so every push of %s would be refused; helios git signers add <name> <public key> allows one first", in.App)
		}
		change = fmt.Sprintf("deploy %s only from commits signed by %s, over push and webhook, and refuse uploaded trees", in.App, p.Who())
		note = "root can still deploy a tree, with helios deploy on the machine or --to root@"
		if p.Requires(in.App) {
			note = in.App + " already deploys only signed commits, so nothing changes"
		} else if d.Store != nil {
			apps, err := d.Store.Apps(ctx)
			if err != nil {
				return nil, err
			}
			if !slices.ContainsFunc(apps, func(a state.App) bool { return a.Name == in.App }) {
				note = in.App + " isn't deployed here yet, and its first push is held to this; " + note
			}
		}
	}
	if in.By != "" {
		change += ", asked by " + in.By
	}
	return &kernel.Plan{Target: in.App, Recovery: kernel.Resume, Steps: []kernel.Step{{
		Name: "require signed", Change: change, Note: note,
		Apply: func(ctx context.Context, out io.Writer) error {
			err := UpdatePolicy(dir, func(p *Policy) error {
				if !in.Off && len(p.Signers) == 0 && len(p.Others) == 0 {
					return errors.New("no signer is allowed any more; plan again")
				}
				p.Require(in.App, in.Off)
				return nil
			})
			if err != nil {
				return policyWriteError(err)
			}
			if in.Off {
				fmt.Fprintf(out, "%s deploys any commit\n", in.App)
			} else {
				fmt.Fprintf(out, "%s deploys only signed commits\n", in.App)
			}
			return nil
		},
	}}}, nil
}

func policyDir(dir string) string {
	if dir == "" {
		return SigningDir
	}
	return dir
}

func policyWriteError(err error) error {
	if errors.Is(err, os.ErrPermission) {
		return fmt.Errorf("changing the signing policy needs root: %w", err)
	}
	return err
}
