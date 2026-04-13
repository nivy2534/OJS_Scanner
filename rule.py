import yaml

class Rule:
    def __init__(self):
        pass

    def loader(self, file):
        try:
            with open(file, 'r') as file:
                data = yaml.safe_load(file)
            
            print(data)
            return data
        except FileNotFoundError:
            print(f"Error: the file {file} was not found")
        except yaml.YAMLError as e:
            print(f"Error parsing YAML file: {e}")
        
