import pandas as pd

arff_file_path = "Training Dataset.arff"

# Read the content of the ARFF file
with open(arff_file_path, 'r') as arff_file:
    arff_content = arff_file.read()

# Find the index where @data starts
data_start_index = arff_content.find('@data') + 5

# Extract the header and data sections from the ARFF content
header_section = arff_content[:data_start_index].strip()
data_section = arff_content[data_start_index:].strip()

# Process the header to convert it into a list of attribute names
header_lines = header_section.split('\n')
header_list = [line.split()[1] for line in header_lines if line.strip().startswith('@attribute')]

# Process the data to convert it into a list of rows
data_lines = data_section.split('\n')
data_list = [line.split(',') for line in data_lines if line.strip()]

# Create a Pandas DataFrame from the header and data lists
df = pd.DataFrame(data_list, columns=header_list)

# # Full Data
# # Specify the path to save the CSV file
# csv_file_path = "Training_Full.csv"
#
# # Write the DataFrame to the CSV file
# df.to_csv(csv_file_path, index=False)

# Drop Data
# Drop the specified columns from the DataFrame
columns_to_drop = ['URL_of_Anchor', 'Links_in_tags', 'SFH', 'Abnormal_URL', 'on_mouseover',
                   "age_of_domain", "DNSRecord", "web_traffic", "Page_Rank",
                   "Google_Index", "Links_pointing_to_page", "Statistical_report"]
data = df.drop(columns_to_drop, axis=1)

# Specify the path to save the CSV file
csv_file_path = "Training.csv"

# # Write the DataFrame to the CSV file
# data.to_csv(csv_file_path, index=False)
