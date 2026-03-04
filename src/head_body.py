
converted_image = r'../images/pic.ppm'
# Step 3: Separate header and body
with open(converted_image, "rb") as f:
    lines = f.readlines()

header = lines[:3]  # Assuming the header is the first 3 lines
body = b"".join(lines[3:])

# Additional: Save header and body separately
with open("pic_header.ppm", "wb") as f:
    f.writelines(header)

with open("pic_body.ppm", "wb") as f:
    f.write(body)
