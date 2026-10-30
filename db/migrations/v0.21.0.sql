-- Workflow diagram (docs/data-model.md §14): where each status sits on the
-- diagram on the workflow page, in diagram units. NULL until it is placed:
-- the page lays out unplaced statuses itself. Like the rest of a version,
-- only a draft's positions change, and a new draft copies them from the
-- version it starts from. Moves are layout only and aren't audited.

ALTER TABLE wf_status ADD COLUMN x double precision, ADD COLUMN y double precision;
