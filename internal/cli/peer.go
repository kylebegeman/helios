package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/kylebegeman/helios/internal/manifest"
	"github.com/kylebegeman/helios/internal/peer"
)

// errPeerName is how a peer's name is refused, whichever command gave it.
var errPeerName = errors.New("a peer's name starts with a lowercase letter and holds only lowercase letters, digits and hyphens; self and edge-provider are taken")

// newPeer is helios peer: the machines this one watches, and the ones
// allowed to read it. Everything it keeps is sealed, and it never shows
// a mesh address or a key.
func newPeer(a *app) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "peer",
		Short: "Other machines this one watches, and the ones allowed to read it. Kept sealed.",
	}
	initialize, key, add, remove := newPeerInit(a), newPeerKey(a), newPeerAdd(a), newPeerRemove(a)
	for _, mutation := range []*cobra.Command{initialize, add, remove} {
		a.guardSecretMutation(mutation, func([]string) string { return manifest.ReservedApp })
	}
	cmd.AddCommand(initialize, key, add, remove, newPeerList(a))
	return cmd
}

// newPeerInit is helios peer init.
func newPeerInit(a *app) *cobra.Command {
	var name, listen string
	var public []string
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Name this machine to its peers and make its peer key. A server also says where it answers them.",
		Long: "Name this machine to its peers and make its peer key. A server also says where it answers them.\n\n" +
			"Running it again changes this machine's name, listen address and public\n" +
			"URLs, and keeps its key.",
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if !peer.ValidName(name) {
				return errPeerName
			}
			self := peer.Self{Name: name}
			if listen != "" {
				ap, err := peer.ParseListen(listen)
				if err != nil {
					return fmt.Errorf("--listen %w", err)
				}
				if len(public) == 0 {
					return errors.New("--listen needs --public too: this machine checks its own public URL before it judges a peer")
				}
				self.Listen = ap.String()
			}
			for _, raw := range public {
				u, err := peer.ParsePublic(raw)
				if err != nil {
					return fmt.Errorf("--public %w", err)
				}
				self.Public = append(self.Public, u)
			}
			store := a.secretsStore()
			if err := a.ensureSecretsKey(store); err != nil {
				return err
			}
			c, err := peer.Load(store)
			if err != nil && !errors.Is(err, peer.ErrNotSet) {
				return err
			}
			if c.Token == "" {
				if c.Token, err = peer.NewToken(); err != nil {
					return err
				}
			}
			c.Self = self
			version, err := peer.Save(store, c)
			if err != nil {
				return err
			}
			fmt.Fprintf(a.stdout, "this machine is %s to its peers (helios's secrets version %d)\nkey: %s\n", name, version, peer.Fingerprint(c.Token))
			return nil
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "this machine's name to its peers")
	cmd.Flags().StringVar(&listen, "listen", "", "where this machine answers its peers: its mesh IP address and a port")
	cmd.Flags().StringArrayVar(&public, "public", nil, "this machine's own public URL, checked before it judges a peer (repeatable)")
	_ = cmd.MarkFlagRequired("name")
	return cmd
}

// newPeerKey is helios peer key.
func newPeerKey(a *app) *cobra.Command {
	var rotate bool
	cmd := &cobra.Command{
		Use:   "key",
		Short: "Print the fingerprint peers register for this machine, never the key itself.",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			store := a.secretsStore()
			c, err := peer.Load(store)
			if err != nil {
				return err
			}
			if rotate {
				if err := a.ensureSecretsKey(store); err != nil {
					return err
				}
				if c.Token, err = peer.NewToken(); err != nil {
					return err
				}
				if _, err := peer.Save(store, c); err != nil {
					return err
				}
			}
			fingerprint := peer.Fingerprint(c.Token)
			fmt.Fprintln(a.stdout, fingerprint)
			if rotate {
				fmt.Fprintf(a.stderr, "register it on every peer with helios peer add %s --key %s; until then they refuse this machine\n", c.Self.Name, fingerprint)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&rotate, "rotate", false, "replace the key; every peer must register the new one")
	// Only a rotation writes; printing the fingerprint waits on nothing.
	a.guardSecretMutation(cmd, func([]string) string {
		if rotate {
			return manifest.ReservedApp
		}
		return ""
	})
	return cmd
}

// newPeerAdd is helios peer add.
func newPeerAdd(a *app) *cobra.Command {
	var mesh, key string
	var public []string
	cmd := &cobra.Command{
		Use:   "add <name>",
		Short: "Watch a peer with --mesh and --public, let it read this machine with --key, or both. Adding again updates it.",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			name := args[0]
			if !peer.ValidName(name) {
				return errPeerName
			}
			watch := mesh != "" || len(public) > 0
			switch {
			case watch && (mesh == "" || len(public) == 0):
				return errors.New("--mesh and --public go together: a watched peer is checked both ways")
			case !watch && key == "":
				return fmt.Errorf("give --mesh and --public to watch %s, --key to let it read this machine, or both", name)
			}
			p := peer.Peer{Name: name}
			if watch {
				var err error
				if p.Mesh, err = peer.ParseMesh(mesh); err != nil {
					return fmt.Errorf("--mesh %w", err)
				}
				for _, raw := range public {
					u, err := peer.ParsePublic(raw)
					if err != nil {
						return fmt.Errorf("--public %w", err)
					}
					p.Public = append(p.Public, u)
				}
			}
			if key != "" && !peer.ValidKey(key) {
				return errors.New("--key must be the sha256:... fingerprint helios peer key prints on that machine")
			}
			store := a.secretsStore()
			c, err := peer.Load(store)
			if err != nil {
				return err
			}
			if err := a.ensureSecretsKey(store); err != nil {
				return err
			}
			var did []string
			if watch {
				c.Peers = slices.DeleteFunc(c.Peers, func(q peer.Peer) bool { return q.Name == name })
				c.Peers = append(c.Peers, p)
				slices.SortFunc(c.Peers, func(x, y peer.Peer) int { return strings.Compare(x.Name, y.Name) })
				did = append(did, "watching "+name)
			}
			if key != "" {
				if c.Observers == nil {
					c.Observers = map[string]string{}
				}
				c.Observers[name] = key
				did = append(did, name+" may read this machine")
			}
			version, err := peer.Save(store, c)
			if err != nil {
				return err
			}
			fmt.Fprintf(a.stdout, "%s (helios's secrets version %d)\n", strings.Join(did, "; "), version)
			return nil
		},
	}
	cmd.Flags().StringVar(&mesh, "mesh", "", "where the peer answers on the mesh, as host:port")
	cmd.Flags().StringArrayVar(&public, "public", nil, "the peer's public URL (repeatable)")
	cmd.Flags().StringVar(&key, "key", "", "the peer's key fingerprint, from helios peer key there, to let it read this machine")
	return cmd
}

// newPeerRemove is helios peer rm.
func newPeerRemove(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "rm <name>",
		Short: "Stop watching a peer and stop letting it read this machine.",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			name := args[0]
			store := a.secretsStore()
			c, err := peer.Load(store)
			if err != nil {
				return err
			}
			watched := slices.ContainsFunc(c.Peers, func(p peer.Peer) bool { return p.Name == name })
			_, observer := c.Observers[name]
			if !watched && !observer {
				return fmt.Errorf("no peer named %s", name)
			}
			c.Peers = slices.DeleteFunc(c.Peers, func(p peer.Peer) bool { return p.Name == name })
			delete(c.Observers, name)
			if err := a.ensureSecretsKey(store); err != nil {
				return err
			}
			version, err := peer.Save(store, c)
			if err != nil {
				return err
			}
			fmt.Fprintf(a.stdout, "%s removed (helios's secrets version %d)\n", name, version)
			return nil
		},
	}
}

// peerRow is a peer as listed: its name, what it is to this machine and
// its public URLs. Never its mesh address or key.
type peerRow struct {
	Name             string   `json:"name"`
	Watched          bool     `json:"watched"`
	ReadsThisMachine bool     `json:"reads_this_machine"`
	Public           []string `json:"public,omitempty"`
}

// newPeerList is helios peer ls.
func newPeerList(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "ls",
		Short: "List the peers by name and public URL. Mesh addresses and keys are never shown.",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			c, err := peer.Load(a.secretsStore())
			notSet := errors.Is(err, peer.ErrNotSet)
			if err != nil && !notSet {
				return err
			}
			rows := peerRows(c)
			if a.json {
				if rows == nil {
					rows = []peerRow{}
				}
				return json.NewEncoder(a.stdout).Encode(rows)
			}
			switch {
			case notSet:
				fmt.Fprintln(a.stdout, "peer watch is not set up here; start with helios peer init --name <name>")
				return nil
			case len(rows) == 0:
				fmt.Fprintln(a.stdout, "no peers; watch one with helios peer add <name> --mesh <host:port> --public <url>")
				return nil
			}
			w := tabwriter.NewWriter(a.stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "NAME\tROLE\tPUBLIC")
			for _, r := range rows {
				var roles []string
				if r.Watched {
					roles = append(roles, "watched")
				}
				if r.ReadsThisMachine {
					roles = append(roles, "reads this machine")
				}
				urls := "-"
				if len(r.Public) > 0 {
					urls = strings.Join(r.Public, " ")
				}
				fmt.Fprintf(w, "%s\t%s\t%s\n", r.Name, strings.Join(roles, ", "), urls)
			}
			return w.Flush()
		},
	}
}

// peerRows joins the watched peers and the observers by name.
func peerRows(c peer.Config) []peerRow {
	byName := map[string]*peerRow{}
	for _, p := range c.Peers {
		byName[p.Name] = &peerRow{Name: p.Name, Watched: true, Public: p.Public}
	}
	for name := range c.Observers {
		if r, ok := byName[name]; ok {
			r.ReadsThisMachine = true
			continue
		}
		byName[name] = &peerRow{Name: name, ReadsThisMachine: true}
	}
	var rows []peerRow
	for _, name := range sortedKeys(byName) {
		rows = append(rows, *byName[name])
	}
	return rows
}
