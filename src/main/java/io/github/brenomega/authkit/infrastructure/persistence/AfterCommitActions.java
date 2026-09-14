package io.github.brenomega.authkit.infrastructure.persistence;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

/** Runs non-transactional store/cache effects only after the SQL transaction commits. */
public final class AfterCommitActions {

    private static final Logger log = LoggerFactory.getLogger(AfterCommitActions.class);

    private AfterCommitActions() {
    }

    public static void run(Runnable action) {
        if (!TransactionSynchronizationManager.isSynchronizationActive()) {
            action.run();
            return;
        }
        TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
            @Override
            public void afterCommit() {
                try {
                    action.run();
                } catch (RuntimeException ex) {
                    log.error("Post-commit side effect failed and requires operational reconciliation", ex);
                }
            }
        });
    }
}
