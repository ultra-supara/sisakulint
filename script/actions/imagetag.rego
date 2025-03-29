package core

default image_tag_not_pinned = false

# Rule: Warn if the image tag is not pinned
image_tag_not_pinned {
    job := input.jobs[_]
    image := job.container.image
    not contains_colon(image)
}

image_tag_not_pinned {
    job := input.jobs[_]
    image := job.container.image
    endswith(image, ":latest")
}

# Helper function to check if the image contains a colon
contains_colon(image) {
    contains(image, ":")
}

# Generate warning messages
missing_image_tag_warnings[result] {
    image_tag_not_pinned
    result := "Warning: The image tag in the container is not pinned. Please use a specific tag or hash."
}
