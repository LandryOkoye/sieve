ALTER TABLE memory_review_events
  DROP CONSTRAINT memory_review_events_action_check;

ALTER TABLE memory_review_events
  ADD CONSTRAINT memory_review_events_action_check
  CHECK (action IN ('validate', 'promote', 'reject', 'mark_false_positive', 'revoke', 'supersede'));
