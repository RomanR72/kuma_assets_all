import json
import os
import pandas as pd
from openpyxl import Workbook

def clean_field(value):
    """Очистка поля от скобок и апострофов"""
    if isinstance(value, list):
        return ', '.join(str(item) for item in value)
    return str(value).replace('[', '').replace(']', '').replace("'", "")

def merge_and_export_to_xlsx(input_dir, output_file):
    """
    Объединяет JSON-файлы и экспортирует в XLSX с разделением по tenantName
    и очисткой специальных полей
    
    :param input_dir: Путь к директории с JSON-файлами
    :param output_file: Путь к результирующему XLSX-файлу
    """
    if not os.path.isdir(input_dir):
        print(f"Директория {input_dir} не существует!")
        return

    tenants_data = {}

    for filename in os.listdir(input_dir):
        if filename.endswith('.json'):
            file_path = os.path.join(input_dir, filename)
            
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    
                    items = data if isinstance(data, list) else [data]
                    
                    for item in items:
                        # Очищаем специальные поля
                        for field in ['fqdn', 'ipAddresses', 'macAddresses']:
                            if field in item:
                                item[field] = clean_field(item[field])
                        
                        tenant = item.get('tenantName', 'Без имени')
                        if tenant not in tenants_data:
                            tenants_data[tenant] = []
                        tenants_data[tenant].append(item)
                
                print(f"Успешно обработан файл: {filename}")
                
            except Exception as e:
                print(f"Ошибка при обработке файла {filename}: {e}")

    try:
        with pd.ExcelWriter(output_file, engine='openpyxl') as writer:
            for tenant, data in tenants_data.items():
                df = pd.DataFrame(data)
                sheet_name = str(tenant)[:31]
                sheet_name = ''.join(c for c in sheet_name if c not in r'[]:*?/\\')
                
                df.to_excel(writer, sheet_name=sheet_name, index=False)
                
                # Автонастройка ширины столбцов
                worksheet = writer.sheets[sheet_name]
                for column in worksheet.columns:
                    max_length = 0
                    column = [cell for cell in column]
                    for cell in column:
                        try:
                            if len(str(cell.value)) > max_length:
                                max_length = len(str(cell.value))
                        except:
                            pass
                    adjusted_width = (max_length + 2) * 1.2
                    worksheet.column_dimensions[column[0].column_letter].width = adjusted_width
            
        print(f"Данные успешно экспортированы в {output_file}")
        print(f"Создано листов: {len(tenants_data)}")
        
    except Exception as e:
        print(f"Ошибка при создании XLSX-файла: {e}")

if __name__ == "__main__":
    input_directory = "response"
    output_filename = "tenant_data_cleaned.xlsx"
    merge_and_export_to_xlsx(input_directory, output_filename)