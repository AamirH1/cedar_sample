// Admin, Developer, and Tester have access to all features and sub-features
permit(
    principal,
    action == Action::"access",
    resource
)
when {
    principal in Persona::"admin"
};

permit(
    principal,
    action == Action::"access",
    resource
)
when {
    principal in Persona::"developer"
};

permit(
    principal,
    action == Action::"access",
    resource
)
when {
    principal in Persona::"tester"
};

// Manager has access to Decom feature, subfeature1 sub-feature, and subfeature3 sub-feature
permit(
    principal,
    action == Action::"access",
    resource == Feature::"feature1"
)
when {
    principal in Persona::"manager"
};

permit(
    principal,
    action == Action::"access",
    resource == SubFeature::"subfeature1"
)
when {
    principal in Persona::"manager"
};

permit(
    principal,
    action == Action::"access",
    resource == SubFeature::"subfeature3"
)
when {
    principal in Persona::"manager"
};

// Analyst has access to subfeature1 sub-feature and subfeature3 sub-feature only
permit(
    principal,
    action == Action::"access",
    resource == SubFeature::"subfeature1"
)
when {
    principal in Persona::"analyst"
};

permit(
    principal,
    action == Action::"access",
    resource == SubFeature::"subfeature3"
)
when {
    principal in Persona::"analyst"
};
