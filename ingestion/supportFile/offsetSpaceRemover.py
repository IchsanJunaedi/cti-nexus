import os

offset_file_path = "offset"
offset_txt_list = os.listdir(offset_file_path)

for file_name in offset_txt_list:
    file_name = offset_file_path + "/" + file_name

    temp_list = []

    try:
        with open(file_name, 'r') as indata:
            raw_offset_data = indata.readlines()
    except FileNotFoundError:
        open(file_name, 'w+')
        with open(file_name, 'r') as indata:
            raw_offset_data = indata.readlines()
            
    for raw_offset in raw_offset_data:
        temp_list.append(raw_offset.strip())

    final_list = []
    
    write_status = False
    for entry in temp_list:
        if str(entry).startswith(" "):
            write_status = True
            entry = str(entry).lstrip().strip()
        else:
            entry = str(entry).strip()
        
        final_list.append(entry)

    if write_status == False:
        pass
    else:
        with open(file_name, 'w') as offset_data_output:
            for entry in final_list:
                offset_data_output.write(str(entry) + "\n")
