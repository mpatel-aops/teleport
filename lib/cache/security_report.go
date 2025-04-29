// Teleport
// Copyright (C) 2025 Gravitational, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package cache

import (
	"context"

	"github.com/gravitational/trace"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/api/types/header"
	"github.com/gravitational/teleport/api/types/secreports"
	"github.com/gravitational/teleport/lib/services"
)

const auditQueryStoreNameIndex = "name"

func newAuditQueryCollection(upstream services.SecReports, w types.WatchKind) (*collection[*secreports.AuditQuery], error) {
	if upstream == nil {
		return nil, trace.BadParameter("missing parameter SecReports")
	}

	return &collection[*secreports.AuditQuery]{
		store: newStore(map[string]func(*secreports.AuditQuery) string{
			auditQueryStoreNameIndex: func(r *secreports.AuditQuery) string {
				return r.GetName()
			},
		}),
		fetcher: func(ctx context.Context, loadSecrets bool) ([]*secreports.AuditQuery, error) {
			var out []*secreports.AuditQuery
			var nextToken string
			for {
				var page []*secreports.AuditQuery
				var err error

				page, nextToken, err = upstream.ListSecurityAuditQueries(ctx, 0 /* default page size */, nextToken)
				if err != nil {
					return nil, trace.Wrap(err)
				}
				out = append(out, page...)
				if nextToken == "" {
					break
				}
			}
			return out, nil
		},
		headerTransform: func(hdr *types.ResourceHeader) *secreports.AuditQuery {
			return &secreports.AuditQuery{
				ResourceHeader: header.ResourceHeader{
					Kind:    hdr.Kind,
					Version: hdr.Version,
					Metadata: header.Metadata{
						Name: hdr.Metadata.Name,
					},
				},
			}
		},
		watch: w,
	}, nil
}

// GetSecurityAuditQuery returns the specified audit query resource.
func (c *Cache) GetSecurityAuditQuery(ctx context.Context, name string) (*secreports.AuditQuery, error) {
	ctx, span := c.Tracer.Start(ctx, "cache/GetSecurityAuditQuery")
	defer span.End()

	getter := genericGetter[*secreports.AuditQuery]{
		cache:       c,
		collection:  c.collections.auditQueries,
		index:       auditQueryStoreNameIndex,
		upstreamGet: c.Config.SecReports.GetSecurityAuditQuery,
		clone: func(a *secreports.AuditQuery) *secreports.AuditQuery {
			return a.Clone()
		},
	}
	out, err := getter.get(ctx, name)
	return out, trace.Wrap(err)
}

// GetSecurityAuditQueries returns a list of all audit query resources.
func (c *Cache) GetSecurityAuditQueries(ctx context.Context) ([]*secreports.AuditQuery, error) {
	ctx, span := c.Tracer.Start(ctx, "cache/GetSecurityAuditQueries")
	defer span.End()

	rg, err := acquireReadGuard(c, c.collections.auditQueries)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	defer rg.Release()

	if !rg.ReadCache() {
		out, err := c.Config.SecReports.GetSecurityAuditQueries(ctx)
		return out, trace.Wrap(err)
	}

	out := make([]*secreports.AuditQuery, 0, rg.store.len())
	for a := range rg.store.resources(auditQueryStoreNameIndex, "", "") {
		out = append(out, a.Clone())
	}

	return out, nil
}

// ListSecurityAuditQueries returns a paginated list of all audit query resources.
func (c *Cache) ListSecurityAuditQueries(ctx context.Context, pageSize int, pageToken string) ([]*secreports.AuditQuery, string, error) {
	ctx, span := c.Tracer.Start(ctx, "cache/ListSecurityAuditQueries")
	defer span.End()

	lister := genericLister[*secreports.AuditQuery]{
		cache:        c,
		collection:   c.collections.auditQueries,
		index:        auditQueryStoreNameIndex,
		upstreamList: c.Config.SecReports.ListSecurityAuditQueries,
		nextToken: func(a *secreports.AuditQuery) string {
			return a.GetMetadata().Name
		},
		clone: func(a *secreports.AuditQuery) *secreports.AuditQuery {
			return a.Clone()
		},
	}
	out, next, err := lister.list(ctx, pageSize, pageToken)
	return out, next, trace.Wrap(err)
}

const securityReportStoreNameIndex = "name"

func newSecurityReportCollection(upstream services.SecReports, w types.WatchKind) (*collection[*secreports.Report], error) {
	if upstream == nil {
		return nil, trace.BadParameter("missing parameter SecReports")
	}

	return &collection[*secreports.Report]{
		store: newStore(map[string]func(*secreports.Report) string{
			securityReportStoreNameIndex: func(r *secreports.Report) string {
				return r.GetName()
			},
		}),
		fetcher: func(ctx context.Context, loadSecrets bool) ([]*secreports.Report, error) {
			var out []*secreports.Report
			var nextToken string
			for {
				var page []*secreports.Report
				var err error

				page, nextToken, err = upstream.ListSecurityReports(ctx, 0 /* default page size */, nextToken)
				if err != nil {
					return nil, trace.Wrap(err)
				}
				out = append(out, page...)
				if nextToken == "" {
					break
				}
			}
			return out, nil
		},
		headerTransform: func(hdr *types.ResourceHeader) *secreports.Report {
			return &secreports.Report{
				ResourceHeader: header.ResourceHeader{
					Kind:    hdr.Kind,
					Version: hdr.Version,
					Metadata: header.Metadata{
						Name: hdr.Metadata.Name,
					},
				},
			}
		},
		watch: w,
	}, nil
}

// GetSecurityReport returns the specified security report resource.
func (c *Cache) GetSecurityReport(ctx context.Context, name string) (*secreports.Report, error) {
	ctx, span := c.Tracer.Start(ctx, "cache/GetSecurityReport")
	defer span.End()

	getter := genericGetter[*secreports.Report]{
		cache:       c,
		collection:  c.collections.secReports,
		index:       securityReportStoreNameIndex,
		upstreamGet: c.Config.SecReports.GetSecurityReport,
		clone: func(r *secreports.Report) *secreports.Report {
			return r.Clone()
		},
	}
	out, err := getter.get(ctx, name)
	return out, trace.Wrap(err)
}

// GetSecurityReports returns a list of all security report resources.
func (c *Cache) GetSecurityReports(ctx context.Context) ([]*secreports.Report, error) {
	ctx, span := c.Tracer.Start(ctx, "cache/GetSecurityReports")
	defer span.End()

	rg, err := acquireReadGuard(c, c.collections.secReports)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	defer rg.Release()

	if !rg.ReadCache() {
		out, err := c.Config.SecReports.GetSecurityReports(ctx)
		return out, trace.Wrap(err)
	}

	out := make([]*secreports.Report, 0, rg.store.len())
	for r := range rg.store.resources(securityReportStoreNameIndex, "", "") {
		out = append(out, r.Clone())
	}

	return out, nil
}

// ListSecurityReports returns a paginated list of all security report resources.
func (c *Cache) ListSecurityReports(ctx context.Context, pageSize int, pageToken string) ([]*secreports.Report, string, error) {
	ctx, span := c.Tracer.Start(ctx, "cache/ListSecurityReports")
	defer span.End()

	lister := genericLister[*secreports.Report]{
		cache:        c,
		collection:   c.collections.secReports,
		index:        securityReportStoreNameIndex,
		upstreamList: c.Config.SecReports.ListSecurityReports,
		nextToken: func(r *secreports.Report) string {
			return r.GetMetadata().Name
		},
		clone: func(r *secreports.Report) *secreports.Report {
			return r.Clone()
		},
	}
	out, next, err := lister.list(ctx, pageSize, pageToken)
	return out, next, trace.Wrap(err)
}

const securityReportStateStoreNameIndex = "name"

func newSecurityReportStateCollection(upstream services.SecReports, w types.WatchKind) (*collection[*secreports.ReportState], error) {
	if upstream == nil {
		return nil, trace.BadParameter("missing parameter SecReports")
	}

	return &collection[*secreports.ReportState]{
		store: newStore(map[string]func(*secreports.ReportState) string{
			securityReportStateStoreNameIndex: func(r *secreports.ReportState) string {
				return r.GetName()
			},
		}),
		fetcher: func(ctx context.Context, loadSecrets bool) ([]*secreports.ReportState, error) {
			var out []*secreports.ReportState
			var nextToken string
			for {
				var page []*secreports.ReportState
				var err error

				page, nextToken, err = upstream.ListSecurityReportsStates(ctx, 0 /* default page size */, nextToken)
				if err != nil {
					return nil, trace.Wrap(err)
				}
				out = append(out, page...)
				if nextToken == "" {
					break
				}
			}
			return out, nil
		},
		headerTransform: func(hdr *types.ResourceHeader) *secreports.ReportState {
			return &secreports.ReportState{
				ResourceHeader: header.ResourceHeader{
					Kind:    hdr.Kind,
					Version: hdr.Version,
					Metadata: header.Metadata{
						Name: hdr.Metadata.Name,
					},
				},
			}
		},
		watch: w,
	}, nil
}

// GetSecurityReportState returns the specified security report state resource.
func (c *Cache) GetSecurityReportState(ctx context.Context, name string) (*secreports.ReportState, error) {
	ctx, span := c.Tracer.Start(ctx, "cache/GetSecurityReportState")
	defer span.End()

	getter := genericGetter[*secreports.ReportState]{
		cache:       c,
		collection:  c.collections.secReportsStates,
		index:       securityReportStateStoreNameIndex,
		upstreamGet: c.Config.SecReports.GetSecurityReportState,
		clone: func(r *secreports.ReportState) *secreports.ReportState {
			return r.Clone()
		},
	}
	out, err := getter.get(ctx, name)
	return out, trace.Wrap(err)
}

// GetSecurityReportsStates returns a list of all security report resources.
func (c *Cache) GetSecurityReportsStates(ctx context.Context) ([]*secreports.ReportState, error) {
	ctx, span := c.Tracer.Start(ctx, "cache/GetSecurityReportsStates")
	defer span.End()

	rg, err := acquireReadGuard(c, c.collections.secReportsStates)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	defer rg.Release()

	if !rg.ReadCache() {
		out, err := c.Config.SecReports.GetSecurityReportsStates(ctx)
		return out, trace.Wrap(err)
	}

	out := make([]*secreports.ReportState, 0, rg.store.len())
	for r := range rg.store.resources(securityReportStateStoreNameIndex, "", "") {
		out = append(out, r.Clone())
	}

	return out, nil
}

// ListSecurityReportsStates returns a paginated list of all security report resources.
func (c *Cache) ListSecurityReportsStates(ctx context.Context, pageSize int, pageToken string) ([]*secreports.ReportState, string, error) {
	ctx, span := c.Tracer.Start(ctx, "cache/ListSecurityReportsStates")
	defer span.End()

	lister := genericLister[*secreports.ReportState]{
		cache:        c,
		collection:   c.collections.secReportsStates,
		index:        securityReportStateStoreNameIndex,
		upstreamList: c.Config.SecReports.ListSecurityReportsStates,
		nextToken: func(r *secreports.ReportState) string {
			return r.GetMetadata().Name
		},
		clone: func(r *secreports.ReportState) *secreports.ReportState {
			return r.Clone()
		},
	}
	out, next, err := lister.list(ctx, pageSize, pageToken)
	return out, next, trace.Wrap(err)
}
