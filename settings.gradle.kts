rootProject.name = "plugin-loader"

include("example:test-component")
findProject(":example:test-component")?.name = "test-component"

