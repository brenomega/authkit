package io.github.brenomega.authkit.infrastructure.email;

public enum EmailTemplateId {
    EMAIL_CONFIRMATION("email-confirmation", true),
    PASSWORD_RECOVERY("password-recovery", true),
    PASSWORD_CHANGED("password-changed", false),
    EMAIL_CHANGE_CONFIRMATION("email-change-confirmation", true),
    EMAIL_CHANGE_REQUESTED("email-change-requested", false),
    EMAIL_CHANGED("email-changed", false),
    EMAIL_CHANGE_CANCELLED("email-change-cancelled", false);

    private final String fileStem;
    private final boolean actionUrlRequired;

    EmailTemplateId(String fileStem, boolean actionUrlRequired) {
        this.fileStem = fileStem;
        this.actionUrlRequired = actionUrlRequired;
    }

    public String fileStem() { return fileStem; }
    public boolean actionUrlRequired() { return actionUrlRequired; }
}
