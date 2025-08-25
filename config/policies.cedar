// Admin persona has access to all features
permit(
    principal in Persona::"admin",
    action,
    resource
);

// Manager persona can access dashboard, reports, and data export
permit(
    principal in Persona::"manager",
    action in [
        Action::"dashboard_access",
        Action::"report_generation",
        Action::"data_export"
    ],
    resource
);

// Analyst persona can only access dashboard
permit(
    principal in Persona::"analyst",
    action == Action::"dashboard_access",
    resource
);

// Feature-based access control
permit(
    principal,
    action,
    resource in Feature::"dashboard_access"
)
when {
    principal.persona in ["admin", "manager", "analyst"]
};

permit(
    principal,
    action,
    resource in Feature::"user_management"
)
when {
    principal.persona == "admin"
};

permit(
    principal,
    action,
    resource in Feature::"system_configuration"
)
when {
    principal.persona == "admin"
};
