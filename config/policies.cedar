// Dynamic group-based authorization policies

// Full access groups (Admin, Developer, Tester)
permit(
    principal,
    action == Action::"access",
    resource
)
when {
    context.groups.contains("e6e00e41-72e6-4b7f-8e99-a3f6d826a961") || // Admin group
    context.groups.contains("2e648c70-58c0-4b94-a9ed-d2aab9323879") || // Developer group  
    context.groups.contains("fab0c659-1d5a-462a-b494-28f86c08d16d")    // Tester group
};

// Manager group: Access to 3DRE
permit(
    principal,
    action == Action::"access",
    resource == Feature::"feature1"
)
when {
    context.groups.contains("e76c4c4a-82ca-4565-a121-ed7aeb0be746") // Manager group
};

permit(
    principal,
    action == Action::"access",
    resource == SubFeature::"subfeature1"
)
when {
    context.groups.contains("e76c4c4a-82ca-4565-a121-ed7aeb0be746") // Manager group
};

permit(
    principal,
    action == Action::"access",
    resource == SubFeature::"subfeature4"
)
when {
    context.groups.contains("e76c4c4a-82ca-4565-a121-ed7aeb0be746") // Manager group
};

// Analyst group: Access to 2RE only
permit(
    principal,
    action == Action::"access",
    resource == SubFeature::"subfeature1"
)
when {
    context.groups.contains("75415da5-ff7d-4d9f-b85c-e98951c229c3") // Analyst group
};

permit(
    principal,
    action == Action::"access",
    resource == SubFeature::"subfeature4"
)
when {
    context.groups.contains("75415da5-ff7d-4d9f-b85c-e98951c229c3") // Analyst group
};
