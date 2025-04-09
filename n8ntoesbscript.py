# -*- coding: utf-8 -*-
"""
Created on Tue Feb 18 13:29:12 2025

@author: mahta
"""

import ast
import json
import xml.etree.ElementTree as ET
import re
from collections import OrderedDict
def key_transform_pairs(pairs):
    """Transform keys by replacing single quotes with double quotes"""
    return OrderedDict((k.replace("'", '"'), v) for k, v in pairs)
# Specify the path to your JSON file
file_path = "C:/Users/felodenz/Desktop/r&d/esb-code-generation-based-on-n8n-master/esb-code-generation-based-on-n8n-master/My_workflow(34).json"
# Open the JSON file and load its content
with open(file_path, 'r') as file:
    content = file.read()  # Read as string
print(type(content),content)
   # extracted_data = json.dump(file)
# Load the extracted JSON data
# print(type(extracted_data))
# extracted_data=extracted_data.replace("'",'"')
extracted_data=json.loads(content)
print(type(extracted_data),extracted_data)
# extracted_data = json.loads(json.dumps(extracted_data))
# Create the root element for the ESB XML
root = ET.Element("api")

# Variable to check if "respondWith" exists and is equal to "text"
respond_with_text_exists = False
respond_with_connection_exists = False


# Flag to track if the first HTTP Request node has been processed
first_http_request_processed = False

# Function to ensure RespondLog and respond are the last elements in outSequence
def ensure_respond_is_last(out_sequence):
    # Remove any existing RespondLog or respond elements
    for child in list(out_sequence):
        if child.tag == "respond" or (child.tag == "sequence" and child.get("key") == "RespondLog"):
            out_sequence.remove(child)
    
    # Add RespondLog and respond as the last elements
    response_log = ET.SubElement(out_sequence, "sequence")
    response_log.set("key", "RespondLog")
    respond_ = ET.SubElement(out_sequence, "respond")

# Function to extract the method and path
def extract_http_method_and_path(json_body):
    http_method = None
    path = None

    # Check if the JSON body has a 'nodes' key
    if 'nodes' in json_body:
        for node in json_body['nodes']:
            if 'path' in node['parameters']:
                if 'httpMethod' in node['parameters']:
                    http_method = node['parameters'].get('httpMethod')
                    path = node['parameters'].get('path')
                    print("http",http_method)
                    print("path",path)
                else:
                    http_method = 'GET'
                    path = node['parameters'].get('path')
                    print("http",http_method)
                    print("path",path)

    return http_method, path

# Create a resource element
resource_element = ET.SubElement(root, "resource")
# Set attributes for the resource element
method, path = extract_http_method_and_path(extracted_data)
resource_element.set("methods", method)
print("masir chie", f'/{path}')
resource_element.set("uri-template", f'/{path}')
# Ensure the element has a closing tag by adding text content
resource_element.text = ""
in_sequence = ET.SubElement(resource_element, "inSequence")
in_sequence.insert(0, ET.Element("sequence", key="IncomingLog"))
out_sequence = ET.SubElement(resource_element, "outSequence")
fault_sequence = ET.SubElement(resource_element, "faultSequence")
default_fault= ET.SubElement(fault_sequence, "sequence")
default_fault.set("key", "DoorsoaDefaultFault")
# Create an ElementTree object
tree = ET.ElementTree(root)

# Function to check if HTTP resquest connection exists as a parent of if node
def is_http_parent_of_if(nodes, connections):
    """
    Checks if any node of type "n8n-nodes-base.httpRequest" is a direct parent of a node of type "n8n-nodes-base.if".
    
    Args:
        nodes (list): List of node dictionaries with metadata.
        connections (dict): Dictionary defining node relationships.
    
    Returns:
        bool: True if an "httpRequest" node is a parent of an "if" node, otherwise False.
    """
    # Convert nodes list into a dictionary for quick lookup
    node_types = {node["name"]: node["type"] for node in nodes}
    
    # Iterate through all connections
    for parent, details in connections.items():
        # Check if the parent node is of type "httpRequest"
        if node_types.get(parent) == "n8n-nodes-base.httpRequest":
            
            # Check its children
            for output in details.get("main", []):
                for child in output:
                    child_node_name = child.get("node")
                    
                    # If the child is of type "if", return True
                    if node_types.get(child_node_name) == "n8n-nodes-base.if":
                        return True
    return False

# # Find httpRequest nodes
# def find_http_node_names(nodes):
#     http_node_names = []
#     http_urls = []
#     for node in nodes:
#         # Check if the node's type is "n8n-nodes-base.if"
#         if node.get('type') == "n8n-nodes-base.httpRequest":
#             # Add the node's name to the list
#             http_node_names.append(node.get('name'))
#             http_urls.append(node['parameters']['url'])
    
#     return http_node_names, http_urls

# Find httpRequest nodes and store their names, URLs, method and type in a single array
def find_http_node_names(nodes):
    http_nodes = []
    for node in nodes:
        # Check if the node's type is "n8n-nodes-base.httpRequest"
        if node.get('type') == "n8n-nodes-base.httpRequest":
            # Extract dynamic variables from URL pattern
            url = node['parameters'].get('url')
            variables = re.findall(r'\{\{([^}]+)\}\}', url)
            print('---------------------------------------------',url,variables)
            for var in variables:
                property_def = ET.SubElement(in_sequence, 'property')
                property_def.set('name', var)
                property_def.set('value', f"$ctx:{var}")
                property_def.set('scope', 'default')
            
            if 'method' in node['parameters']:
                # Append a dictionary with both 'name' and 'url'
                http_nodes.append({
                    'name': node.get('name'),
                    'url': node['parameters'].get('url'),
                    'method': node['parameters'].get('method'),
                    'type': node.get('type')
                })
            else:
                # Append a dictionary with both 'name' and 'url'
                http_nodes.append({
                    'name': node.get('name'),
                    'url': node['parameters'].get('url'),
                    'method': "GET",
                    'type': node.get('type')
                }) 
    
    return http_nodes

# Find the Assignments (Property) (Set) nodes
def find_set_node_names(nodes):
    set_nodes = []
    for node in nodes:
        # Check if the node's type is "n8n-nodes-base.set"
        if node.get('type') == "n8n-nodes-base.set":
            # Add the node's name to the list
            set_nodes.append({
                'name': node.get('name'),
                'assignment': node['parameters'].get('assignments')
                })
    return set_nodes


############################################################
def get_dependency_order(connections):
    # Create a graph from connections
    graph = {node: [] for node in connections.keys()}
    for parent, value in connections.items():
        for conn_list in value.get("main", []):
            for conn in conn_list:
                graph[parent].append(conn["node"])
    
    # Topological sort with order preserved
    visited = set()
    stack = []

    def visit(node):
        if node not in visited:
            visited.add(node)
            # Process children in the exact order they appear
            for neighbor in graph.get(node, []):
                visit(neighbor)
            stack.append(node)

    for node in graph:
        if node not in visited:
            visit(node)

    return stack[::-1]  # Reverse to get the correct order

def rearrange_nodes_by_sequence(nodes, sequence):
    # Create a map of node names to node data
    node_map = {node["name"]: node for node in nodes}
    # Rearrange nodes according to the sequence
    return [node_map[name] for name in sequence if name in node_map]

############################################################
def has_no_if_node(nodes):
    # Check for any node with type "n8n-nodes-base.if"
    return all(node['type'] != "n8n-nodes-base.if" for node in nodes)


def is_http_method_post(json_body):
    def check_post_method(node):
        if 'parameters' in node and 'httpMethod' in node['parameters']:
            if node['parameters']['httpMethod'] == 'POST':
                return True
        return False

    # Check if the JSON body has a 'nodes' key
    if 'nodes' in json_body:
        for node in json_body['nodes']:
            if check_post_method(node):
                return True
    return False

def has_respond_with_text(parameters):
    return parameters.get('respondWith') == 'text'

def get_response_body(parameters):
    if has_respond_with_text(parameters):
        return parameters.get('responseBody')
    return None

def check_for_query_parameters(json_body):
    # Helper function to recursively search for query parameters
    def has_query_param(node):
        if isinstance(node, dict):
            for key, value in node.items():
                if isinstance(value, str) and re.search(r'\.query\.', value):
                    return True
                if has_query_param(value):
                    return True
        elif isinstance(node, list):
            for item in node:
                if has_query_param(item):
                    return True
        return False

    # Check if the JSON body has a 'nodes' key
    if 'nodes' in json_body:
        for node in json_body['nodes']:
            if has_query_param(node['parameters']):
                return True
    return False

def check_for_body_references(json_body):
    # Helper function to recursively search for body references
    def has_body_reference(node):
        if isinstance(node, dict):
            for key, value in node.items():
                if isinstance(value, str) and '.body' in value:
                    return True
                if has_body_reference(value):
                    return True
        elif isinstance(node, list):
            for item in node:
                if has_body_reference(item):
                    return True
        return False

    # Check if the JSON body has a 'nodes' key
    if 'nodes' in json_body:
        for node in json_body['nodes']:
            if has_body_reference(node['parameters']):
                return True
    return False

def find_response_headers(nodes):
    headers = []

    # Iterate through all nodes
    for node in nodes:
        # Check if the node is of type "n8n-nodes-base.respondToWebhook"
        if node['type'] == 'n8n-nodes-base.respondToWebhook':
            # Navigate to the options > responseHeaders > entries
            response_headers = node.get('parameters', {}).get('options', {}).get('responseHeaders', {}).get('entries', [])
            # Extract the header names and values
            for header in response_headers:
                headers.append({
                    "name": header['name'],
                    "value": header['value']
                })
    
    return headers

def check_http_request_response_headers(nodes):
    for node in nodes:
        # Check if the node is of type "n8n-nodes-base.httpRequest"
        if node['type'] == 'n8n-nodes-base.respondToWebhook':
            # Navigate to options > responseHeaders if they exist
            response_headers = node.get('parameters', {}).get('options', {}).get('responseHeaders', None)
            
            # Check if responseHeaders exist
            if response_headers:
                return True
            else:
                return False
    return False

def has_if_node(nodes):
    for node in nodes:
        if node.get('type') == 'n8n-nodes-base.if':
            return True
    return False

#################################################################################
def find_if_node_names(nodes):
    if_node_names = []
    
    for node in nodes:
        # Check if the node's type is "n8n-nodes-base.if"
        if node.get('type') == "n8n-nodes-base.if":
            # Add the node's name to the list
            if_node_names.append(node.get('name'))
    
    return if_node_names
#################################################################################
def find_if_node_children(nodes, connections):
    # Step 1: Find all node names with type 'n8n-nodes-base.if'
    if_node_names = find_if_node_names(nodes)
    
    # Step 2: Find the children of each 'if' node in the connections
    if_node_children = {}
    
    for if_node_name in if_node_names:
        if if_node_name in connections:
            child_nodes = []
            # Traverse the connections structure to find child nodes
            for main_connections in connections[if_node_name]["main"]:
                for connection in main_connections:
                    child_nodes.append(connection["node"])
            if_node_children[if_node_name] = child_nodes
    
    return if_node_children
#################################################################################

def is_http_request_child_of_if(connections, http_node_name, nodes):
    """
    Check if a specific HTTP request node is a child of an 'If' node based on the connections.

    Args:
        connections (dict): The connections dictionary detailing node relationships.
        http_node_name (str): The name of the HTTP request node to check.

    Returns:
        bool: True if the HTTP request node is a child of an 'If' node, False otherwise.
    """
    # Iterate over connections to find 'If' nodes
    for parent_node, connection_data in connections.items():
        for output in connection_data.get("main", []):
            for child in output:
                # Check if the child node matches the given HTTP request node name
                if child.get("node") == http_node_name:
                    # If parent node is an 'If' node, return True
                    if node_type_lookup.get(parent_node) == "n8n-nodes-base.if":
                        return True

    return False
#########################################################################################
def is_node_child_of_webhook(connections, node_name, nodes):
    """
    Check if a specific node is a child of a node of type 'n8n-nodes-base.webhook' based on the connections.

    Args:
        connections (dict): The connections dictionary detailing node relationships.
        node_name (str): The name of the node to check.
        nodes (list): A list of nodes, each containing details including 'name' and 'type'.

    Returns:
        bool: True if the node is a child of a 'n8n-nodes-base.webhook' node, False otherwise.
    """
    # Create a lookup table for node types by name
    node_type_lookup = {node['name']: node['type'] for node in nodes}

    # Iterate over connections to find parent-child relationships
    for parent_node, connection_data in connections.items():
        for output in connection_data.get("main", []):
            for child in output:
                # Check if the child node matches the given node name
                if child.get("node") == node_name:
                    # If the parent node's type is 'n8n-nodes-base.webhook', return True
                    if node_type_lookup.get(parent_node) == "n8n-nodes-base.webhook":
                        return True
    return False
#########################################################################################
def is_node_child_of_set(connections, node_name, nodes):
    """
    Check if a specific node is a child of a node of type 'n8n-nodes-base.webhook' based on the connections.

    Args:
        connections (dict): The connections dictionary detailing node relationships.
        node_name (str): The name of the node to check.
        nodes (list): A list of nodes, each containing details including 'name' and 'type'.

    Returns:
        bool: True if the node is a child of a 'n8n-nodes-base.webhook' node, False otherwise.
    """
    # Create a lookup table for node types by name
    node_type_lookup = {node['name']: node['type'] for node in nodes}

    # Iterate over connections to find parent-child relationships
    for parent_node, connection_data in connections.items():
        for output in connection_data.get("main", []):
            for child in output:
                # Check if the child node matches the given node name
                if child.get("node") == node_name:
                    # If the parent node's type is 'n8n-nodes-base.webhook', return True
                    if node_type_lookup.get(parent_node) == "n8n-nodes-base.set":
                        return True
    return False
###########################################################################################
def is_node_child_of_code(connections, node_name, nodes):
    """
    Check if a specific node is a child of a node of type 'n8n-nodes-base.webhook' based on the connections.

    Args:
        connections (dict): The connections dictionary detailing node relationships.
        node_name (str): The name of the node to check.
        nodes (list): A list of nodes, each containing details including 'name' and 'type'.

    Returns:
        bool: True if the node is a child of a 'n8n-nodes-base.webhook' node, False otherwise.
    """
    # Create a lookup table for node types by name
    node_type_lookup = {node['name']: node['type'] for node in nodes}

    # Iterate over connections to find parent-child relationships
    for parent_node, connection_data in connections.items():
        for output in connection_data.get("main", []):
            for child in output:
                # Check if the child node matches the given node name
                if child.get("node") == node_name:
                    # If the parent node's type is 'n8n-nodes-base.webhook', return True
                    if node_type_lookup.get(parent_node) == "n8n-nodes-base.code":
                        return True
    return False
#########################################################################################


##########################################################################################
def get_condition_operation(conditions):
    """
    Extract the operation value from the conditions if they exist.

    Args:
        conditions (list): A list of condition dictionaries.

    Returns:
        str or None: The operation value if it exists, otherwise None.
    """
    if conditions:
        for condition in conditions:
            operator = condition.get("operator", {})
            operation = operator.get("operation")
            if operation:
                return operation
    return None

#########################################################################################
def find_url_matches(url):
    query_match = re.search(r'query\.(\w+)', url)
    body_match = re.search(r'\{\{\s*\$json\.body\.([\w\[\]\'"\.]+)\s*\}\}', url)
    property_match = re.search(r'\{\{\s*\$json\.([\w\[\]\'"\.]+)\s*\}\}', url)
    header_match = re.search(r'headers\.(\w+)', url)
    route_path_params_match = re.search(r'\{\{\s*params\.([\w\[\]\'"\.]+)\s*\}\}', url)

    # Ensure ESB-compatible syntax by properly escaping special characters
    def escape_for_esb(value):
        if value:
            return value.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&apos;')
        return value

    return {
        "query_match": (query_match, escape_for_esb(f"$ctx:query.param.{query_match.group(1)}") if query_match else None),
        "body_match": (body_match, escape_for_esb(f"json-eval($.{body_match.group(1)}") if body_match else None),
        "property_match": (property_match, escape_for_esb(f"$ctx:{property_match.group(1)}") if property_match else None),
        "header_match": (header_match, escape_for_esb(f"$trp:{header_match.group(1)}") if header_match else None),
        "route_path_params_match": (route_path_params_match, escape_for_esb(f"$ctx:uri.var.{route_path_params_match.group(1)}") if route_path_params_match else None)
    }

#########################################################################################
# def find_children_of_node(connections, node_name):
#     """
#     Find all children of a specific node by its name, including the node itself and recursively traversing all descendants.

#     Args:
#         connections (dict): The connections dictionary detailing node relationships.
#         node_name (str): The name of the node to find children for.

#     Returns:
#         list: A list of node names including the specified node and all its descendants.
#     """
#     children = [node_name]  # Include the node itself in the list

#     # Use a queue to manage nodes for breadth-first traversal
#     queue = [node_name]

#     while queue:
#         current_node = queue.pop(0)
#         if current_node in connections:
#             for output in connections[current_node].get("main", []):
#                 for child in output:
#                     child_node_name = child.get("node")
#                     if child_node_name and child_node_name not in children:
#                         children.append(child_node_name)
#                         queue.append(child_node_name)  # Add the child to the queue for further traversal

#     return children

# def find_children_of_node(connections, nodes, node_name):
#     """
#     Find all children of a specific node by its name that have the type "n8n-nodes-base.httpRequest",
#     including the node itself if it matches, and recursively traversing all descendants.

#     Args:
#         connections (dict): The connections dictionary detailing node relationships.
#         nodes (dict): A dictionary containing node metadata, where keys are node names and values include the node type.
#         node_name (str): The name of the node to find children for.

#     Returns:
#         list: A list of node names of type "n8n-nodes-base.httpRequest", including the specified node if it matches and all its descendants.
#     """
#     children = []

#     # Check if the node itself is of the required type
#     if nodes.get(node_name, {}).get("type") == "n8n-nodes-base.httpRequest":
#         children.append(node_name)

#     # Use a queue to manage nodes for breadth-first traversal
#     queue = [node_name]

#     while queue:
#         current_node = queue.pop(0)
#         if current_node in connections:
#             for output in connections[current_node].get("main", []):
#                 for child in output:
#                     child_node_name = child.get("node")
#                     if child_node_name and child_node_name not in children:
#                         # Only add children of the required type
#                         if nodes.get(child_node_name, {}).get("type") == "n8n-nodes-base.httpRequest":
#                             children.append(child_node_name)
#                         queue.append(child_node_name)  # Add to queue for further traversal

#     return children

def find_children_of_node(connections, nodes, node_name):
    """
    Finds child nodes of a given node that are of type "n8n-nodes-base.httpRequest".
    Traverses through connections until a non-httpRequest node is encountered.

    Args:
        connections (dict): The connections dictionary detailing node relationships.
        nodes (list): A list of node dictionaries with metadata, including node names and types.
        node_name (str): The starting node's name.

    Returns:
        list: A list of node names that are of type "n8n-nodes-base.httpRequest".
    """
    # Convert nodes list to a dictionary for easy lookup
    nodes_dict = {node["name"]: node for node in nodes}

    # List to store matched HTTP nodes
    http_children = []

    # Queue for BFS traversal
    queue = [node_name]

    while queue:
        current_node = queue.pop(0)

        # If the current node is an HTTP node, add it to the result
        if current_node in nodes_dict and nodes_dict[current_node]["type"] == "n8n-nodes-base.httpRequest":
            http_children.append(current_node)

        # If the node has children, continue traversal
        if current_node in connections:
            for output in connections[current_node].get("main", []):
                for child in output:
                    child_node_name = child.get("node")

                    # If the child exists and is of type "httpRequest", add to queue
                    if child_node_name and nodes_dict.get(child_node_name, {}).get("type") == "n8n-nodes-base.httpRequest":
                        queue.append(child_node_name)
                    else:
                        # Stop traversal if a non-httpRequest node is encountered
                        return http_children

    return http_children



##############################################################################################
def extract_nodes_by_names(nodes, children_list):
    """
    Extract nodes whose names are in the provided children list.

    Args:
        nodes (list): List of node dictionaries.
        children_list (list): List of node names to extract.

    Returns:
        list: A list of nodes matching the names in children_list.
    """
    return [node for node in nodes if node["name"] in children_list]
##############################################################################################
# def create_filter(filter_element, node_name):
#     # Define the regular expression pattern to extract the "name" part
#     pattern = r'={{ \$json\.query\.(.*?) }}'
#     # Use re.search to find the match
#     match = re.search(pattern, node["parameters"]["conditions"]["conditions"][0]["leftValue"])
#     target_node = find_node_by_name(extracted_data["nodes"], node_name)
#     # Create a filter element
#     filter_element = ET.SubElement(filter_element, "filter")
#     # Set attributes for the resource element
#     filter_element.set("source", f'$ctx:{match.group(1)}')
#     filter_element.set("regex", target_node["parameters"]["conditions"]["conditions"][0]["rightValue"])
#     return filter_element
########################################################################
def find_node_children(node_name, connections):
    # Check if the given node exists in the connections dictionary
    if node_name in connections:
        children = []
        # Loop through all the connections in the "main" list for the specific node
        for main_connections in connections[node_name]["main"]:
            for connection in main_connections:
                children.append(connection["node"])  # Add the child node
        return children  # Return the children of the given node
    else:
        return []  # Return an empty list if the node has no children or doesn't exist

##################################################################################
def check_http_if_connection(nodes, connections):
    # Create a dictionary to map node names to their respective node objects for quick lookup
    node_dict = {node['name']: node for node in nodes}

    # Iterate through the connections to check for the desired condition
    for parent_node, connection_data in connections.items():
        # Get the node object for the parent
        parent_node_obj = node_dict.get(parent_node)
        
        # Check if the parent node is of type "n8n-nodes-base.httpRequest"
        if parent_node_obj and parent_node_obj['type'] == 'n8n-nodes-base.httpRequest':
            # Look at the children of the parent node
            for main_connection in connection_data['main']:
                for connection in main_connection:
                    # Get the child node
                    child_node = node_dict.get(connection['node'])
                    # Check if the child node is of type "n8n-nodes-base.if"
                    if child_node and child_node['type'] == 'n8n-nodes-base.if':
                        return True  # Found the required connection
    return False  # No matching connection found

###################################################################################

# filter_element = ET.SubElement(in_sequence, "filter")
def process_node(node_name, if_node_children, node_type_lookup, extracted_data, in_sequence, level=0):
    indent = "  " * level
    # Get the children of the current node
    children = if_node_children.get(node_name, [])
    
    # Find the corresponding node in extracted_data
    target_node = next((node for node in extracted_data["nodes"] if node["name"] == node_name), None)
    print("this is target node", target_node)
    # Extract the value for filter source from the node's condition
   # pattern = r'={{ \$json\.query\.(.*?) }}'
    pattern = r'query\.(\w+)'
    pattern = r'={{ \$json\.query\.(.*?) }}'
    match = re.search(pattern, target_node["parameters"]["conditions"]["conditions"][0]["leftValue"])
    
    print("shoko",  f'$ctx:{match.group(1)}')
    
    assign_value = target_node["parameters"]["conditions"]["conditions"][0]["leftValue"]
    # match = re.search(pattern, target_node["parameters"]["conditions"]["conditions"][0]["leftValue"])
    # query_match = re.search(r'query\.(\w+)', target_node["parameters"]["conditions"]["conditions"][0]["leftValue"])
    # body_match = re.search(r'body\.(\w+)', target_node["parameters"]["conditions"]["conditions"][0]["leftValue"])
    # header_match = re.search(r'headers\.(\w+)', target_node["parameters"]["conditions"]["conditions"][0]["leftValue"])
    # route_path_params_match = re.search(r'params\.(\w+)', target_node["parameters"]["conditions"]["conditions"][0]["leftValue"])
    # property_match = re.search(r'=\{\{\s*\$\([^)]+\)\.item\.json\.([\w\.]+)\s*\}\}', target_node["parameters"]["conditions"]["conditions"][0]["leftValue"])

    print("chadore", remove_equals_sign(assign_value))
    # if query_match:
    if find_url_matches(assign_value)["query_match"][0]:
        print("yeke")
    #    create_elements(in_sequence, query_match, '$ctx:query.param.', http_node['url'])
        # Create a filter element
        # param = query_match.group(1)
        # expression = f"$ctx:query.param.{param}"

        param = find_url_matches(assign_value)["query_match"][0].group(1)
        print("parameteresh", param)
        # expression = f"$ctx:query.param.{param}"
        expression = find_url_matches(assign_value)["query_match"][1]
        print(expression)
        filter_element = ET.SubElement(in_sequence, "filter")
        filter_element.set("source", expression)
        filter_element.set("regex", assign_value)

    # elif body_match:
    elif find_url_matches(assign_value)["body_match"][0]:
        print("doe")
      #  create_elements(in_sequence, body_match, 'json-eval($.)', http_node['url'])
        # param = body_match.group(1)
        # expression = f"json-eval($.{param})"# Create a filter element
        
        param = find_url_matches(assign_value)["body_match"][0].group(1) or find_url_matches(assign_value)["body_match"][0].group(2)
        print("parameteresh", param)
        # expression = f"json-eval($.{param})"
        expression = find_url_matches(assign_value)["body_match"][1]
        filter_element = ET.SubElement(in_sequence, "filter")
        filter_element.set("source", expression)
        filter_element.set("regex", assign_value)

    # elif header_match:
    elif find_url_matches(assign_value)["header_match"][0]: 
        print("see")
      #  create_elements(in_sequence, header_match, '$trp:', http_node['url'])
        # param = header_match.group(1)
        # expression = f"$trp:{param}"# Create a filter element
        
        # Retrieve parameter and create expression
        param = find_url_matches(assign_value)["header_match"][0].group(1)
        print("parameteresh", param)
        # expression = f"$trp:{param}"
        expression = find_url_matches(assign_value)["header_match"][1]
        # Create a filter element
        filter_element = ET.SubElement(in_sequence, "filter")
        filter_element.set("source", expression)
        filter_element.set("regex", assign_value)

    # elif route_path_params_match:
    elif find_url_matches(assign_value)["route_path_params_match"][0]:
        print("chare")
     #   create_elements(in_sequence, route_path_params_match, '$ctx:uri.var.', http_node['url'])
        # param = route_path_params_match.group(1)
        # expression = f"$ctx:uri.var.{param}"# Create a filter element
        # Retrieve parameter and create expression
        param = find_url_matches(assign_value)["route_path_params_match"][0].group(1)
        print("parameteresh", param)
        # expression = f"$ctx:uri.var.{param}"
        expression = find_url_matches(assign_value)["route_path_params_match"][1]
        # Create a filter element
        filter_element = ET.SubElement(in_sequence, "filter")
        filter_element.set("source", expression)
        filter_element.set("regex", assign_value)
   
    # elif property_match:
    elif find_url_matches(assign_value)["property_match"][0]:
        print("panje")
     #   create_elements(in_sequence, property_match, '$ctx:', http_node['url'])
        # param = property_match.group(1)
        # expression = f"$ctx:{param}"# Create a filter element
        # Retrieve parameter and create expression
        param = find_url_matches(assign_value)["property_match"][0].group(1)
        print("parameteresh", param)
        # expression = f"$ctx:{param}"
        expression = find_url_matches(assign_value)["property_match"][1]
        print(expression)
        # Create a filter element
        filter_element = ET.SubElement(in_sequence, "filter")
        filter_element.set("source", expression)
        filter_element.set("regex", assign_value)

    # # Create a filter element
    # filter_element = ET.SubElement(in_sequence, "filter")
    # filter_element.set("source", f'$ctx:{match.group(1)}')
    # filter_element.set("regex", target_node["parameters"]["conditions"]["conditions"][0]["rightValue"])


    # Ensure there are two parts for "then" and "else"
    then_part = children[0] if len(children) > 0 else None
    else_part = children[1] if len(children) > 1 else None
    print("this is first child", then_part)
    # Process the "then" part
    if then_part:
        child_type = node_type_lookup.get(then_part)
        print(f"{indent}Then (True) Path:")
        
        then_element = ET.SubElement(filter_element, "then")
        if child_type == "n8n-nodes-base.if":
            print(f"{indent}  Filter Node: {then_part}")
            process_node(then_part, if_node_children, node_type_lookup, extracted_data, then_element, level + 1)
        elif child_type == "n8n-nodes-base.respondToWebhook":
            print(f"{indent}  Payload Node: {then_part}")
            then_node = next((node for node in extracted_data["nodes"] if node['name'] == then_part), None)
            if then_node and then_node['parameters']['respondWith']=="text":
                if then_node and 'responseBody' in then_node['parameters']:
                    then_payload_factory = create_payload_factory_inSeq(then_node['parameters']['responseBody'])
                    then_element.append(then_payload_factory)
            elif then_node and then_node['parameters']['respondWith']=="allIncomingItems":
                print("nacho cheese")
                then_payload_factory = create_payload_factory_for_all_incoming()
                # then_element = ET.SubElement(filter_element, "then")
                then_element.append(then_payload_factory)
                    
        elif child_type == "n8n-nodes-base.set":
            print(f"{indent}  Payload Node: {then_part}")
            then_node = next((node for node in extracted_data["nodes"] if node['name'] == then_part), None)
            print("heyyyy", then_node)
            if "assignments" in then_node["parameters"]:
                if pproperty == True:
                    print("baleee")
                  #  assignments = extract_assignments(extracted_data)
                    assignments_list = []
                    for assignment in then_node['parameters']['assignments']['assignments']:
                        name = assignment.get('name')
                        value = assignment.get('value')
                        assignments_list.append({'name': name, 'value': value})
                        
                    print("inehaa", assignments_list)
                    
                    for property_ in assignments_list:
                        print("pastel")
                        sub_element = ET.SubElement(then_element, "property")
                        sub_element.set("name", property_['name'])
                        sub_element.set("value", str(property_['value']))
                        
                        # Convert each element to a string and add to the list
                    #    then_element.append(sub_element)
                                              
                    # Find children of the node "Property"
                    node_children = find_node_children(then_part, extracted_data['connections'])
                #    property_children = node_children.get(then_part, [])
                    prop_child = node_children[0] 
                    child_type = node_type_lookup.get(prop_child)
                    if child_type == "n8n-nodes-base.respondToWebhook":
                        print(f"{indent}  Payload Node: {then_part}")
                        then_node = next((node for node in extracted_data["nodes"] if node['name'] == prop_child), None)
                        then_payload_factory = create_payload_factory_inSeq(then_node['parameters']['responseBody'])
                        then_element.append(then_payload_factory)
                            
                        
    # Process the "else" part
    if else_part:
        child_type = node_type_lookup.get(else_part)
        print(f"{indent}Else (False) Path:")
        
        else_element = ET.SubElement(filter_element, "else")
        if child_type == "n8n-nodes-base.if":
            print(f"{indent}  Filter Node: {else_part}")
            process_node(else_part, if_node_children, node_type_lookup, extracted_data, else_element, level + 1)
        elif child_type == "n8n-nodes-base.respondToWebhook":
            print(f"{indent}  Payload Node: {else_part}")
            else_node = next((node for node in extracted_data["nodes"] if node['name'] == else_part), None)
            else_payload_factory = create_payload_factory_inSeq(else_node['parameters']['responseBody'])
            else_element.append(else_payload_factory)
        elif child_type == "n8n-nodes-base.set":
            print(f"{indent}  Payload Node: {else_part}")
            else_node = next((node for node in extracted_data["nodes"] if node['name'] == else_part), None)
            print("heyyyy", else_node)
            if "assignments" in else_node["parameters"]:
                if pproperty == True:
                    print("baleee")
                  #  assignments = extract_assignments(extracted_data)
                    assignments_list = []
                    for assignment in else_node['parameters']['assignments']['assignments']:
                        name = assignment.get('name')
                        value = assignment.get('value')
                        assignments_list.append({'name': name, 'value': value})
                        
                    print("inehaa", assignments_list)
                    
                    for property_ in assignments_list:
                        print("pastel")
                        sub_element = ET.SubElement(else_element, "property")
                        sub_element.set("name", property_['name'])
                        sub_element.set("value", str(property_['value']))
                                           
                    # Find children of the node "Property"
                    node_children = find_node_children(else_part, extracted_data['connections'])
                #    property_children = node_children.get(else_part, [])
                    prop_child = node_children[0] 
                    print("baby_pastil:", prop_child)
                    child_type = node_type_lookup.get(prop_child)
                    if child_type == "n8n-nodes-base.respondToWebhook":
                        print(f"{indent}  Payload Node: {else_part}")
                        else_node = next((node for node in extracted_data["nodes"] if node['name'] == prop_child), None)
                        else_payload_factory = create_payload_factory_inSeq(else_node['parameters']['responseBody'])
                        else_element.append(else_payload_factory)
    return filter_element

def process_node_outSeq(node_name, if_node_children, node_type_lookup, extracted_data, in_sequence, level=0):
    indent = "  " * level
    # Get the children of the current node
    children = if_node_children.get(node_name, [])
    
    # Find the corresponding node in extracted_data
    target_node = next((node for node in extracted_data["nodes"] if node["name"] == node_name), None)
    print("this is target node", target_node)
    # Extract the value for filter source from the node's condition
    pattern = r'{{\s*\$json\.(.*?)\s*}}'
    match = re.search(pattern, target_node["parameters"]["conditions"]["conditions"][0]["leftValue"])
    print("chi matche:", match)
    # # Create a filter element
    # filter_element = ET.SubElement(out_sequence, "filter")
    # filter_element.set("source", f'$ctx:{match.group(1)}')
    # filter_element.set("regex", str(target_node["parameters"]["conditions"]["conditions"][0]["rightValue"]))
    assign_value = target_node["parameters"]["conditions"]["conditions"][0]["leftValue"]
    # match = re.search(pattern, target_node["parameters"]["conditions"]["conditions"][0]["leftValue"])
    # query_match = re.search(r'query\.(\w+)', target_node["parameters"]["conditions"]["conditions"][0]["leftValue"])
    # body_match = re.search(r'body\.(\w+)', target_node["parameters"]["conditions"]["conditions"][0]["leftValue"])
    # header_match = re.search(r'headers\.(\w+)', target_node["parameters"]["conditions"]["conditions"][0]["leftValue"])
    # route_path_params_match = re.search(r'params\.(\w+)', target_node["parameters"]["conditions"]["conditions"][0]["leftValue"])
    # property_match = re.search(r'=\{\{\s*\$\([^)]+\)\.item\.json\.([\w\.]+)\s*\}\}', target_node["parameters"]["conditions"]["conditions"][0]["leftValue"])
    
    print("chadore", remove_equals_sign(assign_value))
    # if query_match:
    if find_url_matches(assign_value)["query_match"][0]:
        print("yeke")
    #    create_elements(in_sequence, query_match, '$ctx:query.param.', http_node['url'])
        # Create a filter element
        # param = query_match.group(1)
        # expression = f"$ctx:query.param.{param}"
    
        param = find_url_matches(assign_value)["query_match"][0].group(1)
        print("parameteresh", param)
        # expression = f"$ctx:query.param.{param}"
        expression = find_url_matches(assign_value)["query_match"][1]
        print(expression)
        filter_element = ET.SubElement(in_sequence, "filter")
        filter_element.set("source", expression)
        filter_element.set("regex", assign_value)
    
    # elif body_match:
    elif find_url_matches(assign_value)["body_match"][0]:
        print("doe")
      #  create_elements(in_sequence, body_match, 'json-eval($.)', http_node['url'])
        # param = body_match.group(1)
        # expression = f"json-eval($.{param})"# Create a filter element
        
        param = find_url_matches(assign_value)["body_match"][0].group(1) or find_url_matches(assign_value)["body_match"][0].group(2)
        print("parameteresh", param)
        # expression = f"json-eval($.{param})"
        expression = find_url_matches(assign_value)["body_match"][1]
        filter_element = ET.SubElement(in_sequence, "filter")
        filter_element.set("source", expression)
        filter_element.set("regex", assign_value)
    
    # elif header_match:
    elif find_url_matches(assign_value)["header_match"][0]: 
        print("see")
      #  create_elements(in_sequence, header_match, '$trp:', http_node['url'])
        # param = header_match.group(1)
        # expression = f"$trp:{param}"# Create a filter element
        
        # Retrieve parameter and create expression
        param = find_url_matches(assign_value)["header_match"][0].group(1)
        print("parameteresh", param)
        # expression = f"$trp:{param}"
        expression = find_url_matches(assign_value)["header_match"][1]
        # Create a filter element
        filter_element = ET.SubElement(in_sequence, "filter")
        filter_element.set("source", expression)
        filter_element.set("regex", assign_value)
    
    # elif route_path_params_match:
    elif find_url_matches(assign_value)["route_path_params_match"][0]:
        print("chare")
     #   create_elements(in_sequence, route_path_params_match, '$ctx:uri.var.', http_node['url'])
        # param = route_path_params_match.group(1)
        # expression = f"$ctx:uri.var.{param}"# Create a filter element
        # Retrieve parameter and create expression
        param = find_url_matches(assign_value)["route_path_params_match"][0].group(1)
        print("parameteresh", param)
        # expression = f"$ctx:uri.var.{param}"
        expression = find_url_matches(assign_value)["route_path_params_match"][1]
        # Create a filter element
        filter_element = ET.SubElement(in_sequence, "filter")
        filter_element.set("source", expression)
        filter_element.set("regex", assign_value)
    
    # elif property_match:
    elif find_url_matches(assign_value)["property_match"][0]:
        print("panje")
     #   create_elements(in_sequence, property_match, '$ctx:', http_node['url'])
        # param = property_match.group(1)
        # expression = f"$ctx:{param}"# Create a filter element
        # Retrieve parameter and create expression
        param = find_url_matches(assign_value)["property_match"][0].group(1)
        print("parameteresh", param)
        # expression = f"$ctx:{param}"
        expression = find_url_matches(assign_value)["property_match"][1]
        print(expression)
        # Create a filter element
        filter_element = ET.SubElement(in_sequence, "filter")
        filter_element.set("source", expression)
        filter_element.set("regex", assign_value)
    
    # # Create a filter element
    # filter_element = ET.SubElement(in_sequence, "filter")
    # filter_element.set("source", f'$ctx:{match.group(1)}')
    # filter_element.set("regex", target_node["parameters"]["conditions"]["conditions"][0]["rightValue"])

    # Ensure there are two parts for "then" and "else"
    then_part = children[0] if len(children) > 0 else None
    else_part = children[1] if len(children) > 1 else None
    print("this is first child", then_part)
    # Process the "then" part
    if then_part:
        child_type = node_type_lookup.get(then_part)
        print(f"{indent}Then (True) Path:")
        then_element = ET.SubElement(filter_element, "then")
        if child_type == "n8n-nodes-base.if":
            print(f"{indent}  Filter Node: {then_part}")
            process_node_outSeq(then_part, if_node_children, node_type_lookup, extracted_data, then_element, level + 1)        
        elif child_type == "n8n-nodes-base.respondToWebhook":
            print(f"{indent}  Payload Node: {then_part}")
            then_node = next((node for node in extracted_data["nodes"] if node['name'] == then_part), None)
            if then_node:
                if then_node['parameters']['respondWith']=='text' or then_node['parameters']['respondWith']=='json' :
                    then_payload_factory = create_payload_factory_outSeq(then_node['parameters']['responseBody'])
                    then_element.append(then_payload_factory)
            elif then_node and then_node['parameters']['respondWith']=="allIncomingItems":
                print("nacho cheese outseq")
                then_payload_factory = create_payload_factory_for_all_incoming()
                # then_element = ET.SubElement(filter_element, "then")
                then_element.append(then_payload_factory)
                
        elif child_type == "n8n-nodes-base.set":
            print(f"{indent}  Payload Node: {then_part}")
            then_node = next((node for node in extracted_data["nodes"] if node['name'] == then_part), None)
            print("heyyyy", then_node)
            if "assignments" in then_node["parameters"]:
                if pproperty == True:
                    print("baleee")
                  #  assignments = extract_assignments(extracted_data)
                    assignments_list = []
                    for assignment in then_node['parameters']['assignments']['assignments']:
                        name = assignment.get('name')
                        value = assignment.get('value')
                        assignments_list.append({'name': name, 'value': value})
                        
                    print("inehaa", assignments_list)
                    
                    for property_ in assignments_list:
                        print("pastel")
                        sub_element = ET.SubElement(then_element, "property")
                        sub_element.set("name", property_['name'])
                        sub_element.set("value", str(property_['value']))
                        
                        # Convert each element to a string and add to the list
                    #    then_element.append(sub_element)
                                              
                    # Find children of the node "Property"
                    node_children = find_node_children(then_part, extracted_data['connections'])
                #    property_children = node_children.get(then_part, [])
                    prop_child = node_children[0] 
                    print("baby_pastil:", prop_child)
                    child_type = node_type_lookup.get(prop_child)
                    if child_type == "n8n-nodes-base.respondToWebhook":
                        print(f"{indent}  Payload Node: {then_part}")
                        then_node = next((node for node in extracted_data["nodes"] if node['name'] == prop_child), None)
                        then_payload_factory = create_payload_factory_outSeq(then_node['parameters']['responseBody'])
                        then_element.append(then_payload_factory)
                            
                        
    # Process the "else" part
    if else_part:
        child_type = node_type_lookup.get(else_part)
        print(f"{indent}Else (False) Path:")
        
        else_element = ET.SubElement(filter_element, "else")
        if child_type == "n8n-nodes-base.if":
            print(f"{indent}  Filter Node: {else_part}")
            process_node_outSeq(else_part, if_node_children, node_type_lookup, extracted_data, else_element, level + 1)
        elif child_type == "n8n-nodes-base.respondToWebhook":
            print(f"{indent}  Payload Node: {else_part}")
            else_node = next((node for node in extracted_data["nodes"] if node['name'] == else_part), None)
            if else_node:
                if else_node['parameters']['respondWith']=='text' or else_node['parameters']['respondWith']=='json':
                    else_payload_factory = create_payload_factory_outSeq(else_node['parameters']['responseBody'])
                    else_element.append(else_payload_factory)
            elif else_node and else_node['parameters']['respondWith']=="allIncomingItems":
                print("nacho cheese out")
                else_payload_factory = create_payload_factory_for_all_incoming()
                else_element.append(else_payload_factory)
                       
        elif child_type == "n8n-nodes-base.set":
            print(f"{indent}  Payload Node: {else_part}")
            else_node = next((node for node in extracted_data["nodes"] if node['name'] == else_part), None)
            print("heyyyy", else_node)
            if "assignments" in else_node["parameters"]:
                if pproperty == True:
                    print("baleee")
                  #  assignments = extract_assignments(extracted_data)
                    assignments_list = []
                    for assignment in else_node['parameters']['assignments']['assignments']:
                        name = assignment.get('name')
                        value = assignment.get('value')
                        assignments_list.append({'name': name, 'value': value})
                        
                    print("inehaa", assignments_list)
                    
                    for property_ in assignments_list:
                        print("pastel")
                        sub_element = ET.SubElement(else_element, "property")
                        sub_element.set("name", property_['name'])
                        sub_element.set("value", str(property_['value']))
                                           
                    # Find children of the node "Property"
                    node_children = find_node_children(else_part, extracted_data['connections'])
                #    property_children = node_children.get(else_part, [])
                    prop_child = node_children[0] 
                    print("baby_pastil:", prop_child)
                    child_type = node_type_lookup.get(prop_child)
                    if child_type == "n8n-nodes-base.respondToWebhook":
                        print(f"{indent}  Payload Node: {else_part}")
                        else_node = next((node for node in extracted_data["nodes"] if node['name'] == prop_child), None)
                        else_payload_factory = create_payload_factory_outSeq(else_node['parameters']['responseBody'])
                        else_element.append(else_payload_factory)
    return filter_element


def find_node_by_name(nodes, target_name):
    for node in nodes:
        if node.get('name') == target_name:
            return node
    return None  # Return None if no matching node is found


def find_and_process_filter_sequences(nodes):
    # Step 1: Find all node names with type 'n8n-nodes-base.if'
    if_node_children = find_if_node_children(extracted_data["nodes"], extracted_data["connections"])
    
    # Step 2: Create a lookup dictionary for node names to their types
    node_type_lookup = {node['name']: node['type'] for node in extracted_data["nodes"]}

    # Step 3: Identify the outermost 'if' nodes (those not present as children)
    all_if_nodes = set(if_node_children.keys())
    all_child_nodes = {child for children in if_node_children.values() for child in children}
    outer_if_nodes = all_if_nodes - all_child_nodes
    print("outer kodome", outer_if_nodes)
    # Step 4: Process each outer 'if' node
    for outer_if_node in outer_if_nodes:
        result = check_http_if_connection(extracted_data["nodes"], extracted_data["connections"])
        if result == True:
            print("there is http and if")
            print(f"Processing Filter Sequence starting with Node: {outer_if_node}")
            process_node_outSeq(outer_if_node, if_node_children, node_type_lookup, extracted_data, out_sequence)
        else:
            print("there is just if")
            print(f"Processing Filter Sequence starting with Node: {outer_if_node}")
            process_node(outer_if_node, if_node_children, node_type_lookup, extracted_data, in_sequence)
       
###################################################################################


def check_for_assignments(json_data):
    # Check if the JSON data has a 'nodes' key
    if 'nodes' in json_data:
        for node in json_data['nodes']:
            # Check if the node has 'parameters' and 'assignments' keys
            if 'parameters' in node and 'assignments' in node['parameters']:
                return True
    return False

def extract_assignments(json_data):
    assignments_list = []
    # Check if the JSON body has a 'nodes' key
    if 'nodes' in json_data:
        for node in json_data['nodes']:
            if 'parameters' in node and 'assignments' in node['parameters']:
                for assignment in node['parameters']['assignments']['assignments']:
                    name = assignment.get('name')
                    value = assignment.get('value')
                    assignments_list.append({'name': name, 'value': value})
    return assignments_list

def create_property_elements(properties):
    property_elements = []
    # Create SubElements for all properties
    for property_ in properties:
        sub_element = ET.Element("property")
        sub_element.set("name", property_['name'])
        sub_element.set("value", property_['value'])
        # Convert each element to a string and add to the list
        property_elements.append(ET.tostring(sub_element, encoding='unicode', method='xml'))
    return property_elements
       

# Check if json starts with ={ 
def starts_with_equal_brace(json_string):
    # Define the possible prefixes
    prefixes = ['={ ', '={', '={\n', '={\n ']
    # Strip leading and trailing whitespace for accurate comparison
    stripped_string = json_string.strip()
    # Check if the string starts with any of the specified prefixes
    if any(stripped_string.startswith(prefix) for prefix in prefixes):
        return json_string
    return None

def extract_format_var(response_body):
    # Remove the initial '=' character and parse the JSON
    json_body = response_body.lstrip('={')
    json_body = "{" + json_body  # Add the opening brace to correct the JSON format
    data = json.loads(json_body)

    # Recursive function to extract all keys and detect dynamic or static values
    def extract_all_keys(d, path=''):
        keys = []
        if isinstance(d, dict):
            for k, v in d.items():
                current_path = f'{path}.{k}' if path else k
                if isinstance(v, str) and re.match(r'\{\{\s*[^{}]+\s*\}\}', v):
                    keys.append((current_path, 'dynamic'))
                elif v is None or v == 'null':
                    keys.append((current_path, 'null'))
                else:
                    keys.append((current_path, 'static'))
                    keys.extend(extract_all_keys(v, current_path))
        elif isinstance(d, list):
            for i, item in enumerate(d):
                current_path = f'{path}[{i}]'
                keys.extend(extract_all_keys(item, current_path))
        return keys

    all_keys = extract_all_keys(data)
    
    return all_keys

# def extract_arg_var(response_body):
#     # Regular expression to match values inside {{ ... }} from both $() and $json
#     pattern = re.compile(r'\{\{\s*(\$\([^\)]+\).item.json.body.(.*?)|\$json.(.*?))\s*\}\}')
#     matches = pattern.findall(response_body)
#     print("noooo:",matches)
#     variables = [f'$.{match[1].strip()}' if match[1] else f'$ctx:{match[2].strip()}' for match in matches]
#     return variables


def extract_arg_var(response_body):
    # Regular expression to capture the desired parts
    pattern = re.compile(
        r'\$\(\s*[^)]+\s*\)\.\w+\.json\.body\.(.*?)\s*(?=\}|\s|,)|'  # Matches $('...').item.json.body.<property>
        r'\$json\.body\.(.*?)\s*(?=\}|\s|,)|'  # Matches $json.body.<property>
        r'\$json\.body(\[.*?\].*?|.*?)(?=\s*\}|\s*$)|'  # Matches $json.body[...]
        r'\$json\.(.*?)\s*(?=\}|\s|,)|'  # Matches $json.<property>
        r'\.json\.body\.(.*?)\s*(?=\}|\s|,)|'  # Matches .json.body.<property>
        r'\.json\.body(\[.*?\].*?|.*?)(?=\s*\}|\s*$)|'  # Matches .json.body[...]
        r'\.json\.(.*?)\s*(?=\}|\s|,)'  # Matches .json.<property>
        r'\$\(\s*[^)]+\s*\)\.\w+\.json\.query\.(.*?)\s*(?=\}|\s|,)|'  # Matches $('...').item.json.query.<property>
        r'\$json\.query\.(.*?)\s*(?=\}|\s|,)|'  # Matches $json.query.<property>
        r'\$json\.query(\[.*?\].*?|.*?)(?=\s*\}|\s*$)|'  # Matches $json.query[...]
        r'\.json\.query\.(.*?)\s*(?=\}|\s|,)|'  # Matches .json.query.<property>
        r'\.json\.query(\[.*?\].*?|.*?)(?=\s*\}|\s*$)|'  # Matches .json.query[...]
        r'\$\(\s*[^)]+\s*\)\.\w+\.json\.(.*?)\s*(?=\}|\s|,)|'  # Matches $('...').item.json.<property>
    )
    # Regular expression to match any variable name followed by ' : [', ending with ']'
    pattern_obj = re.compile(r'\"(\w+)\" *: *\[(.*?)\]', re.DOTALL)
    
    # Search for the pattern in the response body
    match = pattern_obj.search(response_body)
    variables = []
    if match:
        variable_name = match.group(1) 
        variables.append('$.')
    elif 'json' in response_body:        
        matches = pattern.findall(response_body)
        # print("Matches:", matches)
        # print("JAVABA:", response_body)
       # variables = []
        for match in matches:
            if match[0] or match[1] or match[2] or match[4] or match[5]:  # Matches for body
                variable = ''.join([m for m in match if m]).strip()
                variables.append(f'$.{variable}')
            elif match[7] or match[8] or match[9] or match[10] or match[11]:
                variable = ''.join([m for m in match if m]).strip()
                variables.append(f'$ctx:query.param.{variable}') 
            elif match[3] or match[6] or match[12]:  # Matches for patterns without body
                variable = ''.join([m for m in match[2:] if m]).strip()
                variables.append(f'$ctx:{variable}')

    else: 
        data = json.loads(response_body)
        variables = [str(value) if value is not None else "null" for value in data.values()]
    return variables


def remove_equals_sign(input_string):
    return input_string.replace('=', '')
     
def extract_format_vari(response_body):
    data = json.loads(response_body)
    variables = list(data.keys())
    return variables

def extract_arg_vari(response_body):
    data = json.loads(response_body)
    variables = [str(value) if value is not None else "null" for value in data.values()]
    return variables

def generate_format_string(response_body):
    # Extract keys from the JSON
    keys = extract_format_var(response_body)

    # Create the format string with $ placeholders and handle null values
    dynamic_counter = 1
    format_string = ', '.join([f'"{key.split(".")[-1]}":"${dynamic_counter}"' if key_type == 'dynamic' else f'"{key.split(".")[-1]}":null' for dynamic_counter, (key, key_type) in enumerate(keys, start=1) if key_type != 'static'])

    # Reconstruct the JSON structure
    reconstructed_json = {}
    placeholder_counter = 1
    for key, key_type in keys:
        parts = key.split('.')
        d = reconstructed_json
        for part in parts[:-1]:
            if part not in d or d[part] is None:
                d[part] = {}
            d = d[part]
        if key_type == 'dynamic':
            d[parts[-1]] = f"${placeholder_counter}"
            placeholder_counter += 1
        elif key_type == 'null':
            d[parts[-1]] = None

    return json.dumps(reconstructed_json, separators=(',', ':'))

def create_payload_factory_for_200_status():
    """
    Create a fixed payloadFactory XML structure for a 200 status code response.
    Returns the payloadFactory element.
    """
    # Create the root <payloadFactory> element
    payload_factory = ET.Element("payloadFactory", {"media-type": "json"})

    # Define the fixed format string
    format_string = (
        '{"status":{"code":$1,"message":"$2"},"meta":{"transactionId":"$3"},'
        '"result":{ "data":null,"status":{"code":$4,"message":"$5"}}}'
    )

    # Add the <format> element
    format_element = ET.SubElement(payload_factory, "format")
    format_element.text = format_string

    # Add the <args> element
    args_element = ET.SubElement(payload_factory, "args")

    # Define the fixed arguments
    fixed_args = [
        {"evaluator": "xml", "expression": "$ctx:statusCode"},
        {"evaluator": "xml", "expression": "$ctx:message"},
        {"evaluator": "xml", "expression": "$ctx:doorsoaRequestId"},
        {"value": "200"},
        {"value": "OK!"},
    ]

    # Add the <arg> elements
    for arg in fixed_args:
        ET.SubElement(args_element, "arg", arg)

    return payload_factory



def create_payload_factory_for_error_status():
    """
    Create a fixed payloadFactory XML structure for a 200 status code response.
    Returns the payloadFactory element.
    """
    # Create the root <payloadFactory> element
    payload_factory = ET.Element("payloadFactory", {"media-type": "json"})

    # Define the fixed format string
    format_string = (
        '{"status":{"code":$1,"message":"$2"},"meta":{"transactionId":"$3"},'
        '"result":{ "data":null,"status":{"code":$4,"message":"$5"}}}'

    )

    # Add the <format> element
    format_element = ET.SubElement(payload_factory, "format")
    format_element.text = format_string

    # Add the <args> element
    args_element = ET.SubElement(payload_factory, "args")

    # Define the fixed arguments
    fixed_args = [
        {"evaluator": "xml", "expression": "$ctx:statusCode"},
        {"evaluator": "xml", "expression": "$ctx:message"},
        {"evaluator": "xml", "expression": "$ctx:doorsoaRequestId"},
        {"evaluator": "xml", "expression": "$ctx:responseStatusCode"},
        {"evaluator": "xml", "expression": "$ctx:responseMessage"},
    ]

    # Add the <arg> elements
    for arg in fixed_args:
        ET.SubElement(args_element, "arg", arg)

    return payload_factory

def create_payload_factory_for_all_incoming():
    """
    Create a fixed payloadFactory XML structure for a 200 status code response.
    Returns the payloadFactory element.
    """
    # Create the root <payloadFactory> element
    payload_factory = ET.Element("payloadFactory", {"media-type": "json"})

    # Define the fixed format string
    format_string = (
        '{"status":{"code":$1,"message":"$2"},"meta":{"transactionId":"$3"},'
        '"result":{ "data":"$4","status":{"code":$5,"message":"$6"}}}'
    )

    # Add the <format> element
    format_element = ET.SubElement(payload_factory, "format")
    format_element.text = format_string

    # Add the <args> element
    args_element = ET.SubElement(payload_factory, "args")

    # Define the fixed arguments
    fixed_args = [
        {"evaluator": "xml", "expression": "$ctx:statusCode"},
        {"evaluator": "xml", "expression": "$ctx:message"},
        {"evaluator": "xml", "expression": "$ctx:doorsoaRequestId"},
        {"evaluator": "xml", "expression": "$."},
        {"value": "200"},
        {"value": "OK!"},
    ]

    # Add the <arg> elements
    for arg in fixed_args:
        ET.SubElement(args_element, "arg", arg)

    return payload_factory


                            
def create_payload_factory_inSeq(response_body):
    # Remove the leading '=' sign
    response_body_clean = remove_equals_sign(response_body)
    print("res:", response_body)

    # Extract format variables and arg variables
    format_vars = extract_format_vari(response_body_clean)
    arg_vars = extract_arg_var(response_body_clean)
    print("format_vars:", format_vars)
    print("arg_vars:", arg_vars)
    # Create the payloadFactory XML structure
    payload_factory = ET.Element("payloadFactory", {"media-type": "json"})

    # Create the format string dynamically using the extracted keys
    format_string = ', '.join([f'"{var}": "${i+1}"' for i, var in enumerate(format_vars)])

    # Add the <format> element
    format_element = ET.SubElement(payload_factory, "format")
    format_element.text = f'{{ {format_string} }}'

    # Add the <args> element
    args_element = ET.SubElement(payload_factory, "args")

    # Create properties for argument expressions first
    existing_props = set()
    for value in arg_vars:
        cleaned_value = remove_equals_sign(value)
        if cleaned_value.startswith('$ctx:') and '.' not in cleaned_value:
            prop_name = cleaned_value.split('$ctx:')[-1]
            if prop_name not in existing_props:
                ET.SubElement(parent_sequence, 'property', {
                    'name': prop_name,
                    'value': f'$ctx:{prop_name}',
                    'scope': 'default'
                })
                existing_props.add(prop_name)
    
    # Add the <arg> elements after ensuring properties exist
    for value in arg_vars:
        cleaned_value = remove_equals_sign(value)
        print("kodomarg", cleaned_value)
        if "ctx"  in cleaned_value or "trp" in cleaned_value:
            ET.SubElement(args_element, "arg", {"evaluator": "xml", "expression": cleaned_value})
        else:    
            ET.SubElement(args_element, "arg", {"evaluator": "json", "expression": cleaned_value})
    print("payyyy", payload_factory)
    return payload_factory


def create_payload_factory_outSeq(response_body):
    # Remove the leading '=' sign
    response_body_clean = remove_equals_sign(response_body)

    # Extract format variables and arg variables
    format_vars = extract_format_vari(response_body_clean)
    arg_vars = extract_arg_var(response_body_clean)
    print(format_vars)
    # Create the payloadFactory XML structure
    payload_factory = ET.Element("payloadFactory", {"media-type": "json"})

    # Create the format string dynamically using the extracted keys
    format_string = ', '.join([f'"{var}": "${i+1}"' for i, var in enumerate(format_vars)])
  #  format_string = generate_format_string(response_body_clean)

    # Add the <format> element
    format_element = ET.SubElement(payload_factory, "format")
    format_element.text = f'{{ {format_string} }}'

    # Add the <args> element
    args_element = ET.SubElement(payload_factory, "args")

    # Create properties for argument expressions first
    existing_props = set()
    for value in arg_vars:
        cleaned_value = remove_equals_sign(value)
        if cleaned_value.startswith('$ctx:') and '.' not in cleaned_value:
            prop_name = cleaned_value.split('$ctx:')[-1]
            if prop_name not in existing_props:
                ET.SubElement(parent_sequence, 'property', {
                    'name': prop_name,
                    'value': f'$ctx:{prop_name}',
                    'scope': 'default'
                })
                existing_props.add(prop_name)
    
    # Add the <arg> elements after ensuring properties exist
    for value in arg_vars:
        cleaned_value = remove_equals_sign(value)
        print("kodomarg", cleaned_value)
        if "ctx"  in cleaned_value or "trp" in cleaned_value:
            ET.SubElement(args_element, "arg", {"evaluator": "xml", "expression": cleaned_value})
        else:    
            ET.SubElement(args_element, "arg", {"evaluator": "json", "expression": cleaned_value})

    return payload_factory

def create_then_else_structure_inSeq(connections, nodes):
    # Extract node names from the "If" list
    if_nodes = connections.get("If", {}).get("main", [])
    print("In ife", if_nodes)
    
    # Ensure there are at least two nodes to create <then> and <else> tags
    if len(if_nodes) >= 2:
        print("BlueBerry")
        then_node_name = if_nodes[0][0]["node"] if if_nodes[0] else None
        else_node_name = if_nodes[1][0]["node"] if if_nodes[1] else None

        # Find the corresponding nodes in the nodes list
        then_node = next((node for node in nodes if node['name'] == then_node_name), None)
        else_node = next((node for node in nodes if node['name'] == else_node_name), None)
        print("BB", then_node)
        print("EE", else_node)
        # Create the XML structure
        root = ET.Element("root")

        if then_node and then_node["type"] == "n8n-nodes-base.respondToWebhook": 
            if then_node['parameters']['respondWith']=="text":
                if then_node and 'responseBody' in then_node['parameters']:
                    then_payload_factory = create_payload_factory_inSeq(then_node['parameters']['responseBody'])
                    then_element = ET.SubElement(filter_element, "then")
                    then_element.append(then_payload_factory)
            elif then_node and then_node['parameters']['respondWith']=="allIncomingItems":
                print("barney")
                then_payload_factory = create_payload_factory_for_all_incoming()
                then_element = ET.SubElement(filter_element, "then")
                then_element.append(then_payload_factory)
                
        elif then_node and then_node["type"] == "n8n-nodes-base.httpRequest" :
            print("Kiwi anbe")
            children = find_children_of_node(extracted_data['connections'], extracted_data['nodes'],then_node['name'])

            print("bachehaye then", children)
            matching_nodes = extract_nodes_by_names(extracted_data['nodes'], children)
            print("kodoma shodan", matching_nodes)
            http_request_nodes = find_http_node_names(matching_nodes)
            print("huh", http_request_nodes)
            then_element = ET.SubElement(filter_element, "then")
            if not http_request_nodes:
                print("No 'n8n-nodes-base.httpRequest' nodes found.")
            # Process each node starting with the first HTTP request node
            process_http_node(http_request_nodes, http_request_nodes[0], then_element, is_last=(len(http_request_nodes) == 1))
            print("Processed first HTTP Request node:", http_request_nodes[0]["name"])            
            # Set the flag to True after processing the first node
            # first_http_request_processed = True
            print("chishodpas", http_request_nodes)
            
        elif then_node and then_node["type"] == "n8n-nodes-base.code":
            print("say js")
            
            jscodenode = then_node["parameters"]["jsCode"]
            print("it has script")
            # The content of script
            transformed_code = transform_js_code(jscodenode)
            print("transformed_js", transformed_code)
            
            then_element = ET.SubElement(filter_element, "then")

            # Create the 'script' element with the 'language' attribute
            script_element = ET.SubElement(then_element, "script")
            script_element.set("language", "js")
            # Add the CDATA section as text content within the script element
        #    script_element.text = transformed_code.strip()  # strip() to remove leading/trailing spaces
            # Manually format the code by ensuring proper indentation
            formatted_code = "\n".join(f"    {line}" for line in transformed_code.strip().splitlines())
        
            # Set the formatted code as text content of the script element
            script_element.text = f"\n{formatted_code}\n"
            
            
            
        if else_node and else_node["type"] == "n8n-nodes-base.respondToWebhook": 
            if else_node['parameters']['respondWith']=="text":            
                if else_node and 'responseBody' in else_node['parameters']:
                    else_payload_factory = create_payload_factory_inSeq(else_node['parameters']['responseBody'])
                    else_element = ET.SubElement(filter_element, "else")
                    else_element.append(else_payload_factory)
            elif else_node and else_node['parameters']['respondWith']=="allIncomingItems":
                else_payload_factory = create_payload_factory_for_all_incoming()
                else_element = ET.SubElement(filter_element, "else")
                else_element.append(else_payload_factory)         
                
        elif else_node and else_node["type"] == "n8n-nodes-base.httpRequest" :
            print("anbe tootfarangi")
            children = find_children_of_node(extracted_data['connections'], extracted_data['nodes'], else_node['name'])
            print("bachehaye else", children)
            matching_nodes = extract_nodes_by_names(extracted_data['nodes'], children)
            print("kodoma shodan", matching_nodes)
            http_request_nodes = find_http_node_names(matching_nodes)
            print("gug", http_request_nodes)
            else_element = ET.SubElement(filter_element, "else")
            if not http_request_nodes:
                print("No 'n8n-nodes-base.httpRequest' nodes found.")
            # Process each node starting with the first HTTP request node
            process_http_node(http_request_nodes, http_request_nodes[0], else_element, is_last=(len(http_request_nodes) == 1))
            print("Processed first HTTP Request node:", http_request_nodes[0]["name"])            
            # Set the flag to True after processing the first node
            # first_http_request_processed = True
            print("chishodpas", http_request_nodes)
            
        elif else_node and else_node["type"] == "n8n-nodes-base.code":
            print("say js")
            
            jscodenode = else_node["parameters"]["jsCode"]
            print("it has script")
            # The content of script
            transformed_code = transform_js_code(jscodenode)
            print("transformed_js", transformed_code)
            
            else_element = ET.SubElement(filter_element, "else")

            # Create the 'script' element with the 'language' attribute
            script_element = ET.SubElement(else_element, "script")
            script_element.set("language", "js")
            # Add the CDATA section as text content within the script element
        #    script_element.text = transformed_code.strip()  # strip() to remove leading/trailing spaces
            # Manually format the code by ensuring proper indentation
            formatted_code = "\n".join(f"    {line}" for line in transformed_code.strip().splitlines())
        
            # Set the formatted code as text content of the script element
            script_element.text = f"\n{formatted_code}\n"
            

            
        # Print the resulting XML string
        xml_str = ET.tostring(root, encoding='unicode', method='xml')
        print(xml_str)
    else:
        print("Not enough nodes to create <then> and <else> tags")

def create_then_else_structure_outSeq(connections, nodes):
    # Extract node names from the "If" list
    if_nodes = connections.get("If", {}).get("main", [])
    print("kodom nodaa", if_nodes)
    # Ensure there are at least two nodes to create <then> and <else> tags
    if len(if_nodes) >= 2:
        then_node_name = if_nodes[0][0]["node"] if if_nodes[0] else None
        else_node_name = if_nodes[1][0]["node"] if if_nodes[1] else None

        print("then_node=", then_node_name)
        # Find the corresponding nodes in the nodes list
        then_node = next((node for node in nodes if node['name'] == then_node_name), None)
        else_node = next((node for node in nodes if node['name'] == else_node_name), None)
        print("then_node=", then_node)
        print("else_node=", else_node)

        # Create the XML structure
        root = ET.Element("root")

        if then_node and then_node["type"] == "n8n-nodes-base.respondToWebhook": 
            if then_node['parameters']['respondWith']=="text" or then_node['parameters']['respondWith']=="json":
                if then_node and 'responseBody' in then_node['parameters']:
                    print("ship outSeq then")
                    then_payload_factory = create_payload_factory_outSeq(then_node['parameters']['responseBody'])
                    then_element = ET.SubElement(filter_element, "then")
                    then_element.append(then_payload_factory)
            elif then_node and then_node['parameters']['respondWith']=="allIncomingItems":
                print("barney outSeq then")
                then_payload_factory = create_payload_factory_for_all_incoming()
                then_element = ET.SubElement(filter_element, "then")
                then_element.append(then_payload_factory)
                
        elif then_node and then_node["type"] == "n8n-nodes-base.code":
            print("say js")
            
            jscodenode = then_node["parameters"]["jsCode"]
            print("it has script")
            # The content of script
            transformed_code = transform_js_code(jscodenode)
            print("transformed_js", transformed_code)
            
            then_element = ET.SubElement(filter_element, "then")

            # Create the 'script' element with the 'language' attribute
            script_element = ET.SubElement(then_element, "script")
            script_element.set("language", "js")
            # Add the CDATA section as text content within the script element
        #    script_element.text = transformed_code.strip()  # strip() to remove leading/trailing spaces
            # Manually format the code by ensuring proper indentation
            formatted_code = "\n".join(f"    {line}" for line in transformed_code.strip().splitlines())
        
            # Set the formatted code as text content of the script element
            script_element.text = f"\n{formatted_code}\n"
            
            
        if else_node and else_node["type"] == "n8n-nodes-base.respondToWebhook": 
            if else_node['parameters']['respondWith']=="text" or else_node['parameters']['respondWith']=="json":   
                if else_node and 'responseBody' in else_node['parameters']:
                    print("ship outSeq else")
                    else_payload_factory = create_payload_factory_outSeq(else_node['parameters']['responseBody'])
                    else_element = ET.SubElement(filter_element, "else")
                    else_element.append(else_payload_factory)
            elif else_node and else_node['parameters']['respondWith']=="allIncomingItems":
                print("barney outSeq else")
                else_payload_factory = create_payload_factory_for_all_incoming()
                else_element = ET.SubElement(filter_element, "else")
                else_element.append(else_payload_factory)
        elif else_node and else_node["type"] == "n8n-nodes-base.code":
            print("say js")
            
            jscodenode = else_node["parameters"]["jsCode"]
            print("it has script")
            # The content of script
            transformed_code = transform_js_code(jscodenode)
            print("transformed_js", transformed_code)
            
            else_element = ET.SubElement(filter_element, "else")

            # Create the 'script' element with the 'language' attribute
            script_element = ET.SubElement(else_element, "script")
            script_element.set("language", "js")
            # Add the CDATA section as text content within the script element
        #    script_element.text = transformed_code.strip()  # strip() to remove leading/trailing spaces
            # Manually format the code by ensuring proper indentation
            formatted_code = "\n".join(f"    {line}" for line in transformed_code.strip().splitlines())
        
            # Set the formatted code as text content of the script element
            script_element.text = f"\n{formatted_code}\n"
            
        # Print the resulting XML string
        xml_str = ET.tostring(root, encoding='unicode', method='xml')
        print(xml_str)
    else:
        print("Not enough nodes to create <then> and <else> tags")
        

def create_elements(parent_element, to_match, expression, url, method):
    # Retrieve parameter and create expression
    param = to_match.group(1)
    # param = to_match.group(1) or to_match.group(2)
    print("parameteresh ine", param)
    # expression = f"{ctx_param}{param}"
    # print(f"Created expression: {expression}")
    # Create and configure the property element for the parameter
    property_element = ET.SubElement(parent_element, "property")
    
    # Extract the last part of the property path using regex
    last_match = re.search(r'[\w\'"]+$', param)
    if last_match:
        last_param = last_match.group(0).strip("'\"")  # Remove quotes if present
        print(f"This Matched property: {last_param}")
        # property_element.set("name", last_param)
    else:
        print("No match found")
        last_param = param
        # property_element.set("name", param)
    property_element.set("name", last_param)
    property_element.set("expression", expression)

    # Define and search for the base URL pattern
    base_url_pattern = re.compile(r'(https://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})')
    match = base_url_pattern.search(url)
    if not match:
        return None  # Handle case where URL pattern is not matched
    base_url = match.group(1)
    
    # Extract the context URL by removing the base URL
    context_url = url.replace(base_url, '')
    print("context", context_url)
   # context_url = re.sub(r'\{\{\s*\$json\.(.*?)\s*\}\}', r'$ctx:\1', context_url)
   # context_url = re.sub(r'\{\{\s*\$\(\s*\'[^\']+\'\s*\)\.?(?:item\.)?json\.(.*?)\s*\}\}', r'$ctx:\1', context_url)
    # Combined regex pattern to match both types of placeholders
    
    # context_url = re.sub(
    #     r'\{\{\s*\$json\.(.*?)\s*\}\}|\{\{\s*\$\(\s*\'[^\']+\'\s*\)\.?(?:item\.)?json\.(.*?)\s*\}\}', 
    #     lambda match: f"$ctx:{match.group(1) or match.group(2)}", 
    #     context_url
    # )
    n_context_url = remove_equals_sign(context_url)
    print("contexte morede nazar", transform_context_updated(n_context_url, last_param))
    # Create and configure the property element for REST URL postfix
    rest_property_element = ET.SubElement(parent_element, "property")
    rest_property_element.set("name", "REST_URL_POSTFIX")
    rest_property_element.set("scope", "axis2")
    if "concat" in transform_context_updated(n_context_url, last_param):
        rest_property_element.set("expression", transform_context_updated(n_context_url, last_param))
        print("expression")
    else:
        rest_property_element.set("value", transform_context_updated(n_context_url, last_param))
        print("value")
    
    # Create and configure the property element for endpoint method
    method_property_element = ET.SubElement(parent_element, "property")
    method_property_element.set("name", "HTTP_METHOD")
    method_property_element.set("scope", "axis2")
    method_property_element.set("value", method)
    
    # Add the outgoing log, send, and response log elements to the in_sequence
    outgoing_log = ET.SubElement(parent_element, "sequence")
    outgoing_log.set("key", "OutgoingLog")
    
def create_send_mediator(url, parent_element):
    # Define and search for the base URL pattern
    base_url_pattern = re.compile(r'(https://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})')
    match = base_url_pattern.search(url)
    if not match:
        return None  # Handle case where URL pattern is not matched
    base_url = match.group(1)
    
    send = ET.SubElement(parent_element, "send")
    send_mediator = ET.SubElement(send, "endpoint")
    send_mediator.set("key", base_url)
    
    response_log = ET.SubElement(parent_element, "sequence")
    response_log.set("key", "ResponseLog")
    
def create_call_mediator(url, parent_element):
    # Define and search for the base URL pattern
    base_url_pattern = re.compile(r'(https://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})')
    match = base_url_pattern.search(url)
    if not match:
        return None  # Handle case where URL pattern is not matched
    base_url = match.group(1)
    
    call = ET.SubElement(parent_element, "call")
    call_mediator = ET.SubElement(call, "endpoint")
    call_mediator.set("key", base_url)
    
    response_log = ET.SubElement(parent_element, "sequence")
    response_log.set("key", "ResponseLog")
    

def create_send_mediator_with_httpadd(url, parent_element):
    # Define and search for the base URL pattern
    base_url_pattern = re.compile(r'(https://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})')
    match = base_url_pattern.search(url)
    if not match:
        return None  # Handle case where URL pattern is not matched
    base_url = match.group(1)
    
    send = ET.SubElement(parent_element, "send")
    endpoint = ET.SubElement(send, "endpoint")
    send_mediator = ET.SubElement(endpoint, "address")
    send_mediator.set("uri", base_url)
    
    # response_log = ET.SubElement(parent_element, "sequence")
    # response_log.set("key", "ResponseLog")
    
def create_call_mediator_with_httpadd(url, parent_element):
    # Define and search for the base URL pattern
    base_url_pattern = re.compile(r'(https://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})')
    match = base_url_pattern.search(url)
    if not match:
        return None  # Handle case where URL pattern is not matched
    base_url = match.group(1)
    
    call = ET.SubElement(parent_element, "call")
    endpoint = ET.SubElement(call, "endpoint")
    call_mediator = ET.SubElement(endpoint, "address")
    call_mediator.set("uri", base_url)
    
    response_log = ET.SubElement(parent_element, "sequence")
    response_log.set("key", "ResponseLog")
    
# def create_property(in_sequence, to_match, ctx_param, value):
#     # Retrieve parameter and create expression
#     # param = to_match.group(1)
#     param = to_match
#     expression = f"{ctx_param}{param}"
#     print(f"Created expression: {expression}")
    
#     # Create and configure the property element for the parameter
#     property_element = ET.SubElement(in_sequence, "property")
#     property_element.set("name", param)
#     property_element.set("expression", expression)
#     property_elements.append(ET.tostring(property_element, encoding='unicode', method='xml'))
    
def create_property(parent_element, param, expression):
    # Retrieve parameter and create expression
    # param = to_match.group(1)
    # param = to_match.group(1) or to_match.group(2)
    print("parameteresh ine", param)
    # expression = f"{ctx_param}{param}"
    # print(f"Created expression: {expression}")
    # Create and configure the property element for the parameter
    property_element = ET.SubElement(parent_element, "property")
    
    # Extract the last part of the property path using regex
    last_match = re.search(r'[\w\'"]+$', param)
    if last_match:
        last_param = last_match.group(0).strip("'\"")  # Remove quotes if present
        print(f"This Matched property: {last_param}")
        # property_element.set("name", last_param)
    else:
        print("No match found")
        last_param = param
        # property_element.set("name", param)
    property_element.set("name", last_param)
    property_element.set("expression", expression)
    

def transform_context(context_url):
    def replacer(match):
        # Capture different parts of the match
        full_path = match.group(1) or match.group(2)
        if full_path.startswith("body."):
            return f"$.{full_path.split('.', 1)[-1]}"
        elif full_path.startswith("query."):
            return f"$ctx:query.param.{full_path.split('.', 1)[-1]}"
        elif full_path.startswith("headers.") or full_path.startswith("header."):
            return f"$trp:{full_path.split('.', 1)[-1]}"
        elif full_path.startswith("params."):
            return f"$ctx:uri.var.{full_path.split('.', 1)[-1]}"
        elif full_path.startswith("$('HTTP Request').item.json.body."):
            return f"$ctx:body.{full_path.split('.', 1)[-1]}"
        else:
            return f"$ctx:{full_path}"

    # Replace dynamic parts in the context URL
    transformed_url = re.sub(
        r'\{\{\s*\$json\.(.*?)\s*\}\}|\{\{\s*\$\(\s*\'[^\']+\'\s*\)\.?(?:item\.)?json\.(.*?)\s*\}\}',
        replacer,
        context_url
    )

    # Split the transformed URL into static and dynamic parts
    parts = re.split(r'(\$\.[^/=?&]+|\$ctx:[^/=?&]+|\$trp:[^/=?&]+)', transformed_url)

    # Reconstruct using concat
    concat_parts = []
    for part in parts:
        if re.match(r'^\$ctx:|^\$trp:|^\$\.', part):  # Dynamic part
            concat_parts.append(part)
        elif part.strip():  # Static part
            # Handle "&amp;" as "&"
            part = part.replace("&amp;", "&")
            concat_parts.append(f"'{part}'")

    return f"concat({', '.join(concat_parts)})"


# def transform_context_updated(context_url, last_property):
#     def replacer(match):
#         # Capture different parts of the match
#         full_path = match.group(1) or match.group(2)
#         if full_path.startswith("body."):
#             return f"$ctx:{full_path.split('.', 1)[-1]}"
#         elif full_path.startswith("query."):
#             return f"$ctx:{full_path.split('.', 1)[-1]}"
#         elif full_path.startswith("headers.") or full_path.startswith("header."):
#             return f"$ctx:{full_path.split('.', 1)[-1]}"
#         elif full_path.startswith("params."):
#             return f"$ctx:{full_path.split('.', 1)[-1]}"
#         elif full_path.startswith("$('HTTP Request').item.json.body."):
#             return f"$ctx:{full_path.split('.', 1)[-1]}"
#         else:
#             # Use last_property if available, otherwise return a default placeholder or empty string
#             return f"$ctx:{last_property}" if last_property else "$ctx:unknown"

#     # Replace dynamic parts in the context URL
#     transformed_url = re.sub(
#         r'\{\{\s*\$json\.(.*?)\s*\}\}|\{\{\s*\$\(\s*\'[^\']+\'\s*\)\.?(?:item\.)?json\.(.*?)\s*\}\}',
#         replacer,
#         context_url
#     )

#     # Split the transformed URL into static and dynamic parts
#     parts = re.split(r'(\$\.[^/=?&]+|\$ctx:[^/=?&]+|\$trp:[^/=?&]+)', transformed_url)

#     # If there's only one part, return it directly
#     if len(parts) == 1 and parts[0].strip():
#         return parts[0].replace("&amp;", "&")  # Handle "&amp;" as "&"

#     # Reconstruct using concat
#     concat_parts = []
#     for part in parts:
#         if re.match(r'^\$ctx:|^\$trp:|^\$\.', part):  # Dynamic part
#             concat_parts.append(part)
#         elif part.strip():  # Static part
#             # Handle "&amp;" as "&"
#             part = part.replace("&amp;", "&")
#             concat_parts.append(f"'{part}'")

#     return f"concat({', '.join(concat_parts)})"




def transform_context_updated(context_url, last_property):
    def replacer(match):
        # Capture different parts of the match
        full_path = match.group(1) or match.group(2)
        if full_path.startswith("body.") or full_path.startswith("query.") or full_path.startswith("headers.") or full_path.startswith("header.") or full_path.startswith("params.") or full_path.startswith("$('HTTP Request').item.json.body."):
            return f"$ctx:{last_property}" if last_property else "$ctx:unknown"
        else:
            # Use last_property if available, otherwise return a default placeholder or empty string
            return f"$ctx:{last_property}" if last_property else "$ctx:unknown"

    # Replace dynamic parts in the context URL
    transformed_url = re.sub(
        r'\{\{\s*\$json\.(.*?)\s*\}\}|\{\{\s*\$\(\s*\'[^\']+\'\s*\)\.?(?:item\.)?json\.(.*?)\s*\}\}',
        replacer,
        context_url
    )

    # Split the transformed URL into static and dynamic parts
    parts = re.split(r'(\$\.[^/=?&]+|\$ctx:[^/=?&]+|\$trp:[^/=?&]+)', transformed_url)

    # If there's only one part, return it directly
    if len(parts) == 1 and parts[0].strip():
        return parts[0].replace("&amp;", "&")  # Handle "&amp;" as "&"

    # Reconstruct using concat
    concat_parts = []
    for part in parts:
        if re.match(r'^\$ctx:|^\$trp:|^\$\.', part):  # Dynamic part
            concat_parts.append(part)
        elif part.strip():  # Static part
            # Handle "&amp;" as "&"
            part = part.replace("&amp;", "&")
            concat_parts.append(f"'{part}'")

    return f"concat({', '.join(concat_parts)})"


# def handle_query_param(connections, node):
#     # Handle query.x in conditions
#    # for node in nodes:
#         if node["type"] == "n8n-nodes-base.if":
#             conditions = node["parameters"]["conditions"]["conditions"]
#             for condition in conditions:
#                 left_value = condition["leftValue"]
#                 query_match = re.search(r'query\.(\w+)', left_value)
#                 if query_match:
#                     param = query_match.group(1)
#                     expression = f"$ctx:query.param.{param}"
#                     print(f"Created expression: {expression}")
#                     print("kojas")
#                     property_element = ET.SubElement(in_sequence, "property")
#                     # Set attributes for the resource element
#                     property_element.set("name", param)
#                     property_element.set("expression", expression)

def handle_query_param(connections, node, sequence):
    # Handle query.x in conditions
    if node["type"] == "n8n-nodes-base.if":
        conditions = node["parameters"]["conditions"]["conditions"]
        for condition in conditions:
            left_value = condition["leftValue"]

            # Match query parameters
            query_match = re.search(r'query\.(\w+)', left_value)
            if query_match:
                param = query_match.group(1)
                expression = f"$ctx:query.param.{param}"
                print(f"Created expression: {expression}")
                property_element = ET.SubElement(sequence, "property")
                property_element.set("name", param)
                property_element.set("expression", expression)

            # Match $json.body['...'] pattern
            body_match = re.search(r"\$json\.body\['(.*?)'\]", left_value)
            if body_match:
                param = body_match.group(1)
                expression = f"json-eval(${param})"
                print(f"Created expression for body: {expression}")
                property_element = ET.SubElement(sequence, "property")
                property_element.set("name", param)
                property_element.set("expression", expression)


def process_http_node(http_request_nodes, node, parent_element, is_last=False):
        if node["type"] == "n8n-nodes-base.httpRequest":
            url = node["url"]
            # query_match = re.search(r'query\.(\w+)', url)
            # # query_match = re.search(r'\{\{\s*query\.([\w\[\]\'"\.]+)\s*\}\}', url)
            # # body_match = re.search(
            # #     r'\{\{\s*\$json\.body(?:\[\s*[\'"](\w+)[\'"]\s*\]|\.(\w+))\s*\}\}',
            # #     url
            # # )
            # body_match = re.search(r'\{\{\s*\$json\.body\.([\w\[\]\'"\.]+)\s*\}\}', url)
            # # property_match = re.search(r'\{\{\s*\$json\.(\w+)\s*\}\}', url)
            # property_match = re.search(r'\{\{\s*\$json\.([\w\[\]\'"\.]+)\s*\}\}', url)
            # header_match = re.search(r'headers\.(\w+)', url)
            # # header_match = re.search(r'\{\{\s*headers\.([\w\[\]\'"\.]+)\s*\}\}', url)
            # # route_path_params_match = re.search(r'params\.(\w+)', url)
            # route_path_params_match = re.search(r'\{\{\s*params\.([\w\[\]\'"\.]+)\s*\}\}', url)

            http_nodes= find_http_node_names(extracted_data["nodes"])
            print("Node names with type 'n8n-nodes-base.HTTPREQUEST':", http_request_nodes)
        #    print("url ones", http_nodes['url'])
            for i, http_node in enumerate(http_request_nodes):
                if node['name']== http_node['name']:
                    print("esme node", http_node['name'])
                    print("kann", http_node['url'])
                    # if query_match:
                    if find_url_matches(url)["query_match"][0]:
                        print("coco", http_node['url'])
                        # Retrieve parameter and create expression
                        param = find_url_matches(url)["query_match"][0].group(1)
                        print("parameteresh", param)
                        # expression = f"$ctx:query.param.{param}"
                        expression = find_url_matches(url)["query_match"][1]
                        print(f"Created expression: {expression}")                        
                        create_elements(parent_element, find_url_matches(url)["query_match"][0], expression, http_node['url'], http_node['method'])
                    # elif body_match:
                    elif find_url_matches(url)["body_match"][0]:
                        print("body match found:", find_url_matches(url)["body_match"][0].group(1))
                        print("sib", http_node['url'])
                        # Retrieve parameter and create expression
                        # param = body_match.group(1)
                        # Use the first non-None group (depending on which format matched)
                        param = find_url_matches(url)["body_match"][0].group(1) or find_url_matches(assign_value)["body_match"][0].group(2)
                        print("parameteresh", param)
                        # expression = f"json-eval($.{param})"
                        expression = find_url_matches(url)["body_match"][1]
                        print(f"Created expression: {expression}")
                        create_elements(parent_element, find_url_matches(url)["body_match"][0], expression, http_node['url'], http_node['method'])
                    # elif header_match:
                    elif find_url_matches(url)["header_match"][0]:
                        print("lavashak", http_node['url'])
                        # Retrieve parameter and create expression
                        param = find_url_matches(url)["header_match"][0].group(1)
                        print("parameteresh", param)
                        # expression = f"$trp:{param}"
                        expression = find_url_matches(url)["header_match"][1]
                        print(f"Created expression: {expression}")
                        create_elements(parent_element, find_url_matches(url)["header_match"][0], expression, http_node['url'], http_node['method'])
                    # elif route_path_params_match:
                    elif find_url_matches(url)["route_path_params_match"][0]:
                        print("gol", http_node['url'])
                        # Retrieve parameter and create expression
                        param = find_url_matches(url)["route_path_params_match"][0].group(1)
                        print("parameteresh", param)
                        # expression = f"$ctx:uri.var.{param}"
                        expression = find_url_matches(url)["route_path_params_match"][1]
                        print(f"Created expression: {expression}")
                        create_elements(parent_element, find_url_matches(url)["route_path_params_match"][0], expression, http_node['url'], http_node['method'])
                    # elif property_match: 
                    elif find_url_matches(url)["property_match"][0]:
                        if find_url_matches(url)["property_match"][0]:
                            # Get the full property path
                            property_path = find_url_matches(url)["property_match"][0].group(1)
                            # Extract the last part after the final dot
                            last_property = property_path.split('.')[-1]
                            print(f"Matched property: {last_property}")
                        else:
                            print("No match found")
                        print("candy bar", http_node['url'])
                        # Retrieve parameter and create expression
                        param = find_url_matches(url)["property_match"][0].group(1)
                        print("parameteresh", param)
                        # expression = f"$ctx:{param}"
                        expression = find_url_matches(url)["property_match"][1]
                        print(f"Created expression: {expression}")
                        create_elements(parent_element, find_url_matches(url)["property_match"][0], expression, http_node['url'], http_node['method'])
                    else:
                        # in this case there is no parameter in the url 
                        # Define and search for the base URL pattern
                        base_url_pattern = re.compile(r'(https://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})')
                        match = base_url_pattern.search(http_node['url'])
                        if not match:
                            return None  # Handle case where URL pattern is not matched
                        base_url = match.group(1)
                        
                        # Extract the context URL by removing the base URL
                        context_url = url.replace(base_url, '')
                       # context_url = re.sub(r'\{\{\s*\$json\.(.*?)\s*\}\}', r'$ctx:\1', context_url)
                       # context_url = re.sub(r'\{\{\s*\$\(\s*\'[^\']+\'\s*\)\.?(?:item\.)?json\.(.*?)\s*\}\}', r'$ctx:\1', context_url)
                        # Combined regex pattern to match both types of placeholders
                        context_url = re.sub(
                            r'\{\{\s*\$json\.(.*?)\s*\}\}|\{\{\s*\$\(\s*\'[^\']+\'\s*\)\.?(?:item\.)?json\.(.*?)\s*\}\}', 
                            lambda match: f"$ctx:{match.group(1) or match.group(2)}", 
                            context_url
                        )
                        # Create and configure the property element for REST URL postfix
                        n_context_url = remove_equals_sign(context_url)
                        print("contexte morede nazar", transform_context_updated(n_context_url,""))
               
                        rest_property_element = ET.SubElement(parent_element, "property")
                        rest_property_element.set("name", "REST_URL_POSTFIX")
                        rest_property_element.set("scope", "axis2")
                        # rest_property_element.set("value", remove_equals_sign(context_url))
                        # rest_property_element.set("expression", transform_context_updated(n_context_url))
                        if "concat" in transform_context_updated(n_context_url, ""):
                            rest_property_element.set("expression", transform_context_updated(n_context_url,""))
                            print("expression")
                        else: 
                            rest_property_element.set("value", transform_context_updated(n_context_url,""))
                            print("value")
                        print("methode node", http_node['method'])
                        # Create and configure the property element for endpoint method
                        method_property_element = ET.SubElement(parent_element, "property")
                        method_property_element.set("name", "HTTP_METHOD")
                        method_property_element.set("scope", "axis2")
                        method_property_element.set("value", http_node['method'])
                        
                        # Add the outgoing log, send, and response log elements to the in_sequence
                        outgoing_log = ET.SubElement(parent_element, "sequence")
                        outgoing_log.set("key", "OutgoingLog")
                        
                        # send = ET.SubElement(in_sequence, "send")
                        # send_mediator = ET.SubElement(send, "endpoint")
                        # send_mediator.set("key", base_url)
                        
                        # response_log = ET.SubElement(in_sequence, "sequence")
                        # response_log.set("key", "ResponseLog")

                    if i == len(http_request_nodes) - 1:  # Check if it's the last node
                        print("ryouu", http_node)
                        print(f"Processing the last HTTP node: {http_node['name']} with URL: {http_node['url']}")
                        create_send_mediator_with_httpadd(http_node['url'], parent_element)
                        # respond_ = ET.SubElement(out_sequence, "respond") 
                        response_log = ET.SubElement(out_sequence, "sequence")
                        response_log.set("key", "ResponseLog")
                    else:
                        print(f"Processing HTTP node: {http_node['name']}")  
                        create_call_mediator_with_httpadd(http_node['url'], parent_element)
        
                    # # Add filter for statusCode
                    # filter_element = ET.SubElement(parent_element, "filter")
                    # filter_element.set("source", "statusCode")
                    # filter_element.set("regex", "200")
            
                    # then_element = ET.SubElement(filter_element, "then")
                    # else_element = ET.SubElement(filter_element, "else")
            
                    # # # Add fixed error payload to "else"
                    # # error_payload = ET.SubElement(else_element, "errorPayload")
                    # # error_payload.text = "Fixed error payload response."
                    # # Create and configure the property element for endpoint method
                    # responseMessage_property_element = ET.SubElement(else_element, "property")
                    # responseMessage_property_element.set("name", "responseMessage")
                    # responseMessage_property_element.set("scope", "default")
                    # responseMessage_property_element.set("type", "STRING")
                    # responseMessage_property_element.set("value", "Unauthorized!")
                    
                    # statusCode_property_element = ET.SubElement(else_element, "property")
                    # statusCode_property_element.set("name", "statusCode")
                    # statusCode_property_element.set("scope", "default")
                    # statusCode_property_element.set("type", "INTEGER")
                    # statusCode_property_element.set("value", "520")
                    
                    # # Create and configure the property element for endpoint method
                    # message_property_element = ET.SubElement(else_element, "property")
                    # message_property_element.set("name", "message")
                    # message_property_element.set("scope", "default")
                    # message_property_element.set("type", "STRING")
                    # message_property_element.set("value", 'Service Provider Error!')
                    
                    # # Create and configure the property element for endpoint method
                    # HTTPSC_property_element = ET.SubElement(else_element, "property")
                    # HTTPSC_property_element.set("name", "HTTP_SC")
                    # HTTPSC_property_element.set("scope", "axis2")
                    # HTTPSC_property_element.set("type", "STRING")
                    # HTTPSC_property_element.set("value", "520")
                    
                    # payload_factory_element = create_payload_factory_for_error_status()
                    # else_element.append(payload_factory_element)
                    # # If last node, add fixed 200 payload to "then"
                    # if is_last:
                        
                    #     # Create and configure the property element for endpoint method
                    #     statusCode_property_element = ET.SubElement(then_element, "property")
                    #     statusCode_property_element.set("name", "statusCode")
                    #     statusCode_property_element.set("scope", "default")
                    #     statusCode_property_element.set("type", "INTEGER")
                    #     statusCode_property_element.set("value", "200")
                        
                    #     # Create and configure the property element for endpoint method
                    #     message_property_element = ET.SubElement(then_element, "property")
                    #     message_property_element.set("name", "message")
                    #     message_property_element.set("scope", "default")
                    #     message_property_element.set("type", "STRING")
                    #     message_property_element.set("value", 'OK!')
                        
                    #     # Create and configure the property element for endpoint method
                    #     HTTPSC_property_element = ET.SubElement(then_element, "property")
                    #     HTTPSC_property_element.set("name", "HTTP_SC")
                    #     HTTPSC_property_element.set("scope", "axis2")
                    #     HTTPSC_property_element.set("type", "STRING")
                    #     HTTPSC_property_element.set("value", "200")
                        
                    #  #   fixed_payload = ET.SubElement(then_element, "fixedPayload")                        
                    #     payload_factory_element = create_payload_factory_for_200_status()
                    #     then_element.append(payload_factory_element)

                    # else:
                    #     # Handle the next node in the "then" part
                    #     next_index = http_request_nodes.index(node) + 1
                    #     if next_index < len(http_request_nodes):
                    #         process_http_node(http_request_nodes, http_request_nodes[next_index], then_element, is_last=(next_index == len(http_request_nodes) - 1))

def handle_property(connections, nodes):
    # Handle query.x in conditions
    for node in nodes:
        if node["name"] == "If":
            conditions = node["parameters"]["conditions"]["conditions"]
            for condition in conditions:
                left_value = condition["leftValue"]
                query_match = re.search(r'json\.(\w+)', left_value)
                if query_match:
                    param = query_match.group(1)
                    expression = f"$ctx:{param}"
                    print(f"Created expression: {expression}")
                    
                    property_element = ET.SubElement(in_sequence, "property")
                    # Set attributes for the resource element
                    property_element.set("name", param)
                    property_element.set("expression", expression)
                    
def find_js_code_node(nodes):
   # for node in nodes:
        # Check if 'parameters' and 'jsCode' are in the node
        if 'parameters' in node and 'jsCode' in node['parameters']:
            return node['parameters']['jsCode']  # Return the node containing jsCode
   # return None  # Return None if no such node is found

def transform_js_code(js_code):
    # Replace the $input.item.json references with mc.getProperty('...')
    transformed_code = re.sub(r'\$input\.item\.json\.(\w+)', r"mc.getProperty('\1')", js_code)
    
    # Replace the return statement with mc.setPayloadJSON({...})
    transformed_code = re.sub(r'return\s*\{\s*json:\s*\{(.*?)\}\s*\}\s*;', r"mc.setPayloadJSON({\1});", transformed_code)
    
    # Wrap the transformed code in CDATA section
    cdata_wrapped_code = f"<![CDATA[\n{transformed_code}\n]]>"

    return cdata_wrapped_code

def check_for_uri_params(expression):
    # Regular expression to match ={{ $json.params.<variable> }}
    pattern = r'=\{\{\s*\$json\.params\.\w+\s*\}\}'

    # Use re.search to check if the pattern exists in the expression
    match = re.search(pattern, expression)

    # Return True if the pattern is found, otherwise return False
    return bool(match)

def extract_param_after_json_params(expression):
    # Regular expression to match and capture the parameter after json.params
    pattern = r'=\{\{\s*\$json\.params\.(\w+)\s*\}\}'

    # Use re.search to find the match
    match = re.search(pattern, expression)

    # If a match is found, return the captured parameter
    if match:
        return match.group(1)
    else:
        return None  # Return None if no match is found


def find_node_order(connections):
    # Create a reverse lookup to identify parent nodes for each node
    parent_lookup = {}
    
    # Fill parent_lookup by reversing the child-parent relationship from the connections
    for parent, connection_data in connections.items():
        for main_connection in connection_data["main"]:
            for connection in main_connection:
                child = connection["node"]
                parent_lookup[child] = parent

    # Find the outermost nodes (nodes that are not children of any other node)
    outermost_nodes = []
    for node in connections:
        if node not in parent_lookup:
            outermost_nodes.append(node)

    # Perform a DFS-like traversal to determine the order of nodes
    node_order = []

    def traverse(node):
        if node in node_order:
            return  # Avoid adding duplicate nodes
        node_order.append(node)
        # Traverse the children of the current node
        if node in connections:
            for main_connection in connections[node]["main"]:
                for connection in main_connection:
                    traverse(connection["node"])

    # Traverse from each outermost node
    for node in outermost_nodes:
        traverse(node)

    return node_order

# Get the node order
node_order = find_node_order(extracted_data['connections'])
# Create a dictionary to map node names to their respective node objects
node_dict = {node['name']: node for node in extracted_data['nodes']}

node_type_lookup = {node['name']: node['type'] for node in extracted_data["nodes"]}
print(node_type_lookup)

# Reverse the nodes list
#extracted_data["nodes"].reverse()

# Get the sequence of node names
sequence = get_dependency_order(extracted_data['connections'])
print("Sequence of nodes:", sequence)

# Rearrange the nodes array
rearranged_nodes = rearrange_nodes_by_sequence(extracted_data['nodes'], sequence)
extracted_data['nodes']= rearranged_nodes
# print("Rearranged nodes:")
# print(json.dumps(rearranged_nodes, indent=2))

###################################################################################33

# Identify the children of "If" nodes that are of type "Respond to Webhook"
webhook_children_of_if = set()

# Iterate through the connections dictionary to find the children of "If" nodes
for node_name, connection_data in extracted_data['connections'].items():
    # Check if the node is an "If" node
    if node_name == "If":
        # Loop through the main connections
        for main_connection in connection_data["main"]:
            for connection in main_connection:
                # Check if the connected node is a "Respond to Webhook" node
                if connection["node"].startswith("Respond to Webhook"):
                    webhook_children_of_if.add(connection["node"])

print("kaaable", webhook_children_of_if)
# Identify the children of "If" nodes that are of type "code"
code_children_of_if = set()
node_types = {node["name"]: node["type"] for node in extracted_data['nodes']}

# Iterate through all connections
for parent, details in extracted_data['connections'].items():
    # Check if the parent node is of type "if"
    if node_types.get(parent) == "n8n-nodes-base.if":
        
        # Check its children
        for output in details.get("main", []):
            for child in output:
                child_node_name = child.get("node")
                
                # If the child is of type "if", return True
                if node_types.get(child_node_name) == "n8n-nodes-base.code": 
                    code_children_of_if.add(child_node_name)

print("hccof", code_children_of_if)
# Track processed nodes to avoid duplicates
processed_nodes = set()


# Iterate over the nodes in the order defined by node_order
for node_name in node_order:
    # if node_name in processed_nodes:
    #     continue  # Skip already processed nodes
    # processed_nodes.add(node_name)
    
    node = node_dict.get(node_name)
    if node:
        # Process the node
        # # Iterate over the nodes and extract the httpMethod and path
        # for node in extracted_data["nodes"]:
        # Skip nodes that are "Respond to Webhook" and are children of an "If" node
        if node["name"] in webhook_children_of_if:
            continue
        # Also skip nodes that are "code" and are children of an "If" node
        if node["name"] in code_children_of_if:
            continue
        # Process the remaining nodes
        print(f"Processing node: {node['name']}")
        # Check if there is property
        pproperty = check_for_assignments(extracted_data)
        # Check if any HTTP Request node contains responseHeaders
        has_response_headers = check_http_request_response_headers(extracted_data["nodes"])
        # Check if the httpMethod is POST
        result = is_http_method_post(extracted_data)     
        # Check if "Respond to Webhook" exists in "HTTP Request"
        exists = is_http_parent_of_if(extracted_data['nodes'], extracted_data["connections"])
        # Check for query parameters
        has_query_params = check_for_query_parameters(extracted_data)
        # Check for Body reference
        has_body_refs = check_for_body_references(extracted_data)
        # Check for js script
        js_code_node = find_js_code_node(extracted_data["nodes"])


      #  if "assignments" in node["parameters"]:
        if node["type"] == 'n8n-nodes-base.set':
            if pproperty == True:
                print("leeee")
                assignments = extract_assignments(extracted_data["nodes"])
                print("these are assignments", assignments)
                property_elements = []
                set_nodes = find_set_node_names(extracted_data["nodes"])

                print("Node names with type 'n8n-nodes-base.set':", set_nodes)
              #  print("lists of assignments", assignmnts)
                for set_node in set_nodes:
                    if node['name']== set_node['name']:
                        print("esme node", set_node['name'])
                        print("assignmnt esh", set_node['assignment'])

                        for property_ in set_node['assignment']['assignments']:
                            print("hamash bahahm", property_)
                            # uri_param = check_for_uri_params(str(property_['value']))
                            assign_value= str(property_['value'])
                            # query_match = re.search(r'query\.(\w+)', assign_value)
                            # body_match = re.search(r'body\.(\w+)', assign_value)
                            # property_match = re.search(r'\{\{\s*\$json\.([\w\[\]\.]+)\s*\}\}', assign_value)
                            # header_match = re.search(r'headers\.(\w+)', assign_value)
                            # route_path_params_match = re.search(r'params\.(\w+)', assign_value)
                    
                            # if query_match:
                            if find_url_matches(assign_value)["query_match"][0]:
                                print("coco property_")
                                param = find_url_matches(assign_value)["query_match"][0].group(1)
                                print("parameteresh", param)
                                # expression = f"$ctx:query.param.{param}"
                                expression = find_url_matches(assign_value)["query_match"][1]
                                print(f"Created expression: {expression}")
                                create_property(in_sequence, param, expression)                       
                            
                            # elif body_match:
                            elif find_url_matches(assign_value)["body_match"][0]:
                                print("sib property_")
                                param = find_url_matches(assign_value)["body_match"][0].group(1) or find_url_matches(assign_value)["body_match"][0].group(2)
                                print("parameteresh", param)
                                # expression = f"json-eval($.{param})"
                                expression = find_url_matches(assign_value)["body_match"][1]
                                print(f"Created expression: {expression}")
                                create_property(in_sequence, param, expression)    
                                # create_property(in_sequence, find_url_matches(assign_value)["body_match"].group(1), 'json-eval($.)', assign_value)
                                
                            # elif header_match:
                            elif find_url_matches(assign_value)["header_match"][0]: 
                                print("lavashak property_")
                                # Retrieve parameter and create expression
                                param = find_url_matches(assign_value)["header_match"][0].group(1)
                                print("parameteresh", param)
                                # expression = f"$trp:{param}"
                                expression = find_url_matches(assign_value)["header_match"][1]
                                print(f"Created expression: {expression}")
                                create_property(in_sequence, param, expression)
                         
                            elif find_url_matches(assign_value)["route_path_params_match"][0]:
                                print("gol property_")
                                # Retrieve parameter and create expression
                                param = find_url_matches(assign_value)["route_path_params_match"][0].group(1)
                                print("parameteresh", param)
                                # expression = f"$ctx:uri.var.{param}"
                                expression = find_url_matches(assign_value)["route_path_params_match"][1]
                                print(f"Created expression: {expression}")
                                create_property(in_sequence, param, expression)
                      
                            # elif property_match:
                            elif find_url_matches(assign_value)["property_match"][0]:
                                print("candy bar property_")
                                # Retrieve parameter and create expression
                                param = find_url_matches(assign_value)["property_match"][0].group(1)
                                print("parameteresh", param)
                                # expression = f"$ctx:{param}"
                                expression = find_url_matches(assign_value)["property_match"][1]
                                print(f"Created expression: {expression}")
                                create_property(in_sequence, param, expression)          
                            else:
                                print("inja property e")
                                sub_element = ET.SubElement(in_sequence, "property")
                                sub_element.set("name", property_['name'])
                                sub_element.set("value", str(property_['value']))
                                
                                # Convert each element to a string and add to the list
                                property_elements.append(ET.tostring(sub_element, encoding='unicode', method='xml'))
        # Handling switch component
        if "rules" in node["parameters"]:
            print("chimigi")
            
        # Handling if component
        if node["type"] == "n8n-nodes-base.if":
            if_node_names = find_if_node_names(extracted_data["nodes"])
            print("Node names with type 'n8n-nodes-base.if':", if_node_names)
            if_node_children = find_if_node_children(extracted_data["nodes"], extracted_data["connections"])
            
            operation = get_condition_operation(node["parameters"]["conditions"]["conditions"])
            print("Operation in conditions:", operation)
            
                    
            # if method is POST
            if result == True:
                print("now is ON")
                query_pattern = r'={{ \$json\.query\.(.*?) }}'
#                body_pattern = r'\.body\.(\w+)\s*\}\}'
                body_pattern = r"\$json\.body\['(.*?)'\]|\.body\.(\w+)\s*\}\}"
                property_pattern = r'={{ \$json\.(.*?) }}'
                # if there is query parameter
                if has_query_params == True:
                    if bool(re.search(query_pattern, node["parameters"]["conditions"]["conditions"][0]["leftValue"])) == True:
                        handle_query_param(extracted_data["connections"], node, in_sequence)

                        # Define the regular expression pattern to extract the "name" part
                        pattern = r'={{ \$json\.query\.(.*?) }}'
                        # Use re.search to find the match
                        match = re.search(pattern, node["parameters"]["conditions"]["conditions"][0]["leftValue"])
        
                        # Create a filter element
                        filter_element = ET.SubElement(in_sequence, "filter")
                        # Set attributes for the resource element
                        filter_element.set("source", f'$ctx:{match.group(1)}')
                        filter_element.set("regex", node["parameters"]["conditions"]["conditions"][0]["rightValue"])
            
                        create_then_else_structure_inSeq(extracted_data["connections"], extracted_data["nodes"])
            
                        # Ensure the element has a closing tag by adding text content
                        filter_element.text = ""
                        print("panir")
    
                elif pproperty == True:
                    if bool(re.search(property_pattern, node["parameters"]["conditions"]["conditions"][0]["leftValue"])) == True:
                        print("It has property condition")
                    #    handle_property(extracted_data["connections"], extracted_data["nodes"])
                        # # Define the regular expression pattern to extract the "name" part
                        pattern = r'={{ \$json\.(.*?) }}'
                        # Use re.search to find the match
                        match = re.search(pattern, node["parameters"]["conditions"]["conditions"][0]["leftValue"])
                        print("bebinam property", bool(match))
                        # Create a filter element
                        filter_element = ET.SubElement(in_sequence, "filter")
                        # Set attributes for the resource element
                        filter_element.set("source", f'$ctx:{match.group(1)}')
                        filter_element.set("regex", node["parameters"]["conditions"]["conditions"][0]["rightValue"])
            
                        create_then_else_structure_inSeq(extracted_data["connections"], extracted_data["nodes"])
              
                # if there is body in request 
                if has_body_refs == True:
                    print("chishodeeee")
                    handle_query_param(extracted_data["connections"], node, in_sequence)
                    if bool(re.search(body_pattern, node["parameters"]["conditions"]["conditions"][0]["leftValue"])) == True:
                        print("it has body")
                        # Define the regular expression pattern to extract the "name" part
                   #     pattern = r'\.body\.(\w+)\s*\}\}'
                        pattern = r"\$json\.body\['(.*?)'\]|\.body\.(\w+)\s*\}\}"
                        # Use re.search to find the match
                        match = re.search(pattern, node["parameters"]["conditions"]["conditions"][0]["leftValue"])
                        print("bebinam body", bool(match))
                        print("match", match,
                              "match esh chie", match.group(1))
                        # Create a filter element
                        filter_element = ET.SubElement(in_sequence, "filter")
                        # Set attributes for the resource element
                        # filter_element.set("source", f'$.{match.group(1)}')
                        
                        if operation == "equals":
                            filter_element.set("source", f'json-eval($.{match.group(1)})')
                            filter_element.set("regex", node["parameters"]["conditions"]["conditions"][0]["rightValue"])
                            print("nemune filter")
                        elif operation == "notEmpty":
                            filter_element.set("xpath", f'json-eval($.{match.group(1)})')
                            print("filter ine")
                         
                        create_then_else_structure_inSeq(extracted_data["connections"], extracted_data["nodes"])
                # If "Respond to Webhook" exists in "HTTP Request"
                if exists == True:
                    print("candle")
                    if len(if_node_names)==1: 
                        respond_with_connection_exists = True
                            
                        # Define the regular expression pattern to extract the "name" part
                        pattern = r'{{\s*\$\(["\']?Code["\']?\)\.item\.json\.(.*?)\s*}}'
                        # Use re.search to find the match
                        match = re.search(pattern, node["parameters"]["conditions"]["conditions"][0]["leftValue"])
                
                        # Create a filter element
                        filter_element = ET.SubElement(out_sequence, "filter")
                
                        # Set attributes for the resource element
                        if operation == "equals":
                            filter_element.set("regex", str(node["parameters"]["conditions"]["conditions"][0]["rightValue"]))
                            filter_element.set("source", f'$axis2:{match.group(1)}')
                        elif operation == "notEmpty":
                            filter_element.set("xpath", f'$axis2:{match.group(1)}')
                            
                        create_then_else_structure_outSeq(extracted_data["connections"], extracted_data["nodes"])
                
                        # Ensure the element has a closing tag by adding text content
                        filter_element.text = ""
                        print("coconut oil")
                        response_log = ET.SubElement(out_sequence, "sequence")
                        response_log.set("key", "RespondLog")
                        respond_ = ET.SubElement(out_sequence, "respond") 
                        
                    elif len(if_node_names) > 1:
                        find_and_process_filter_sequences(node)
                        print("If nodes and their children:", if_node_children)
                        break
                    
            # if the method is GET    
            # If "Respond to Webhook" exists in "HTTP Request"
            elif exists == True:
                print("parvane")
                if len(if_node_names)==1:   
                    respond_with_connection_exists = True
                        
                    # Define the regular expression pattern to extract the "name" part
                    pattern = r'{{\s*\$json\.(.*?)\s*}}'
                    # Use re.search to find the match
                    match = re.search(pattern, node["parameters"]["conditions"]["conditions"][0]["leftValue"])
            
                    # Create a filter element
                    filter_element = ET.SubElement(out_sequence, "filter")
            
                    # Set attributes for the resource element
                    if operation == "equals":
                        filter_element.set("source", f'$axis2:{match.group(1)}')
                        filter_element.set("regex", str(node["parameters"]["conditions"]["conditions"][0]["rightValue"]))
                    elif operation == "notEmpty":
                        filter_element.set("xpath", f'$axis2:{match.group(1)}')
                        
                    create_then_else_structure_outSeq(extracted_data["connections"], extracted_data["nodes"])
            
                    # Ensure the element has a closing tag by adding text content
                    filter_element.text = ""
                    print("coconut")
                    response_log = ET.SubElement(out_sequence, "sequence")
                    response_log.set("key", "RespondLog")
                    respond_ = ET.SubElement(out_sequence, "respond") 
                    
                elif len(if_node_names) > 1:
                    find_and_process_filter_sequences(node)
                    print("If nodes and their children:", if_node_children)
                    break

            else:
                #check if there is query parameters
                ##
                # payload_factory_body = create_payload_factory_inSeq(response_body)
                # payload_factory = ET.SubElement(in_sequence, "payloadFactory")
                # payload_factory.append(payload_factory_body)
                #handle query parameter(s)
    
                # if has_query_params == True:
                if len(if_node_names)==1:
                    print("chi be chie")
                    # Define the regular expression pattern to extract the "name" part
                    pattern = r'={{ \$json\.query\.(.*?) }}'
                    # Use re.search to find the match
                    match = re.search(pattern, node["parameters"]["conditions"]["conditions"][0]["leftValue"])

                    handle_query_param(extracted_data["connections"], node, in_sequence)
    
                    # Create a filter element
                    filter_element = ET.SubElement(in_sequence, "filter")
                    # Set attributes for the filter element
                    if operation == "equals":
                        filter_element.set("source", f'$ctx:{match.group(1)}')
                        filter_element.set("regex", node["parameters"]["conditions"]["conditions"][0]["rightValue"])
                        print("4khune")
                    elif operation == "notEmpty":
                        filter_element.set("xpath", f'$$ctx:{match.group(1)}')
                     
                    create_then_else_structure_inSeq(extracted_data["connections"], extracted_data["nodes"])
                    
                    # Ensure the element has a closing tag by adding text content
                    filter_element.text = ""
                    
                    loopback = ET.SubElement(in_sequence, "loopback")
                
                elif len(if_node_names) > 1:
                    find_and_process_filter_sequences(node)
                    print("If nodes and their children:", if_node_children)
                    break
        

        # Handling js code component            
        if js_code_node:
            print("it has script", js_code_node)
            # The content of script
            transformed_code = transform_js_code(js_code_node)
            print(transformed_code)
            # Create the 'script' element with the 'language' attribute
            script_element = ET.SubElement(in_sequence, "script")
            script_element.set("language", "js")
            # Add the CDATA section as text content within the script element
        #    script_element.text = transformed_code.strip()  # strip() to remove leading/trailing spaces
            # Manually format the code by ensuring proper indentation
            formatted_code = "\n".join(f"    {line}" for line in transformed_code.strip().splitlines())
        
            # Set the formatted code as text content of the script element
            script_element.text = f"\n{formatted_code}\n"
    
        # if has_query_params:
        #     if node["type"] == "n8n-nodes-base.httpRequest":
        #         handle_query_param(extracted_data["connections"], extracted_data["nodes"])
        
        if node["type"] == "n8n-nodes-base.httpRequest" and not first_http_request_processed:
            if is_http_request_child_of_if(extracted_data['connections'], node['name'], extracted_data['nodes']) == True:
                print("San sebastian", node['name'])

                # http_request_nodes = find_http_node_names(extracted_data["nodes"])
                # if not http_request_nodes:
                #     print("No 'n8n-nodes-base.httpRequest' nodes found.")
                # # Process each node starting with the first HTTP request node
                # process_http_node(http_request_nodes, http_request_nodes[0], filter_element, is_last=(len(http_request_nodes) == 1))
                # print("Processed first HTTP Request node:", http_request_nodes[0]["name"]) 
                # first_http_request_processed = True
                
            elif is_node_child_of_webhook(extracted_data['connections'], node['name'], extracted_data['nodes']) == True:
                print("San Jose", node['name'])
                handle_query_param(extracted_data["connections"], node, in_sequence)
                # Filter the nodes with type "n8n-nodes-base.httpRequest"
              #   http_request_nodes = [node for node in extracted_data['nodes'] if node["type"] == "n8n-nodes-base.httpRequest"]
                children = find_children_of_node(extracted_data['connections'], extracted_data['nodes'], node['name'])
                print("bachehaye http", children)
                matching_nodes = extract_nodes_by_names(extracted_data['nodes'], children)
                print("kodoma shodan", matching_nodes)
                http_request_nodes = find_http_node_names(matching_nodes)
                # http_request_nodes = find_http_node_names(extracted_data["nodes"])
                if not http_request_nodes:
                    print("No 'n8n-nodes-base.httpRequest' nodes found.")
                # Process each node starting with the first HTTP request node
                process_http_node(http_request_nodes, http_request_nodes[0], in_sequence, is_last=(len(http_request_nodes) == 1))
                print("Processed first HTTP Request node:", http_request_nodes[0]["name"])            
                # Set the flag to True after processing the first node
                first_http_request_processed = True
                # print("chishodpas", http_request_nodes)
                
            elif is_node_child_of_set(extracted_data['connections'], node['name'], extracted_data['nodes']) == True or is_node_child_of_code(extracted_data['connections'], node['name'], extracted_data['nodes']) == True:
                print("San diego", node['name'])
                handle_query_param(extracted_data["connections"], node, in_sequence)
                # Filter the nodes with type "n8n-nodes-base.httpRequest"
              #   http_request_nodes = [node for node in extracted_data['nodes'] if node["type"] == "n8n-nodes-base.httpRequest"]
                http_request_nodes = find_http_node_names(extracted_data["nodes"])
                if not http_request_nodes:
                    print("No 'n8n-nodes-base.httpRequest' nodes found.")
                # Process each node starting with the first HTTP request node
                process_http_node(http_request_nodes, http_request_nodes[0], in_sequence, is_last=(len(http_request_nodes) == 1))
                print("Processed first HTTP Request node:", http_request_nodes[0]["name"]) 
                # Set the flag to True after processing the first node
                first_http_request_processed = True
            else:
                print("San Marco", node['name'])

        # Handling respond to Webhook component
        if node["type"] == "n8n-nodes-base.respondToWebhook":
            if exists == True:     
                print("shoko")
                if has_response_headers == True:
                      # Get the headers from the respondToWebhook nodes
                      response_headers = find_response_headers(extracted_data["nodes"])
                      print("Response Headers:", response_headers)
                      for headers_ in response_headers:
                          print("pastel")
                          header_element = ET.SubElement(out_sequence, "header")
                          cleaned_value = remove_equals_sign(headers_['value'])  # Remove equals sign if present
                          print("kodomarg", cleaned_value)
                          if "$json"  in cleaned_value:
                              print("pineapple", cleaned_value)
                             # pattern = r'={{ \$json\.(.*?) }}'
                              pattern = r'{{\s*\$json\.(.*?)\s*}}'
                              # Use re.search to find the match
                              match = re.search(pattern, cleaned_value)
                              print("bebinam chie", bool(match))                            
                              header_element.set("name", headers_['name'])
                              header_element.set("expression", f'$ctx:{match.group(1)}')
                              header_element.set("scope", "transport")                            
                          else:        
                              header_element.set("name", headers_['name'])
                              header_element.set("value", str(headers_['value']))
                              header_element.set("scope", "transport")
                print("sugar")            
                response_body = node["parameters"].get("responseBody", "")
                response_body = remove_equals_sign(response_body)
                payload_factory_body = create_payload_factory_outSeq(response_body)
        #      payload_factory = ET.SubElement(in_sequence, "payloadFactory")
                out_sequence.append(payload_factory_body)
                # Note: RespondLog and respond will be added at the end of processing
            #     respond_with_connection_exists = True
    
            #     #     # Create a filter element
            #     filter_element = ET.SubElement(out_sequence, "filter")
            # #     # Set attributes for the resource element
            #     filter_element.set("source", "$axis2:HTTP_SC")
            #     filter_element.set("regex", "200")
    
            #     create_then_else_structure_outSeq(extracted_data["connections"], extracted_data["nodes"])
    
            #     # Ensure the element has a closing tag by adding text content
            #     filter_element.text = ""
            else: 
                if has_response_headers == True:
                    # Get the headers from the respondToWebhook nodes
                    response_headers = find_response_headers(extracted_data["nodes"])
                    print("Response Headers:", response_headers)
                    for headers_ in response_headers:
                        print("pastel")
                        header_element = ET.SubElement(in_sequence, "header")
                        cleaned_value = remove_equals_sign(headers_['value'])  # Remove equals sign if present
                        print("kodomarg", cleaned_value)
                        if "$json"  in cleaned_value:
                            print("pineapple", cleaned_value)
                           # pattern = r'={{ \$json\.(.*?) }}'
                            pattern = r'{{\s*\$json\.(.*?)\s*}}'
                            # Use re.search to find the match
                            match = re.search(pattern, cleaned_value)
                            print("bebinam chie", bool(match))                            
                            header_element.set("name", headers_['name'])
                            header_element.set("expression", f'$ctx:{match.group(1)}')
                            header_element.set("scope", "transport")                            
                        else:        
                            header_element.set("name", headers_['name'])
                            header_element.set("value", str(headers_['value']))
                            header_element.set("scope", "transport")
                print("sugar")            
                response_body = node["parameters"].get("responseBody", "")
                response_body = remove_equals_sign(response_body)
                payload_factory_body = create_payload_factory_inSeq(response_body)
          #      payload_factory = ET.SubElement(in_sequence, "payloadFactory")
                in_sequence.append(payload_factory_body)
                
            # if result == True:
            #     print("It is POST")
            # elif result == False:
            #     if has_query_params == True:
            #         print("it is Get req and it has payload:", response_body)
            #         response_body = remove_equals_sign(response_body)
      
            #         payload_factory_body = create_payload_factory_inSeq(response_body)
            #         payload_factory = ET.SubElement(in_sequence, "payloadFactory")
            #         payload_factory.append(payload_factory_body)
    
        # elif node["name"] == "HTTP Request":
        #     handle_query_param(extracted_data["connections"], extracted_data["nodes"])
        # Check if respondWith is "text" and handle responseBody
     # !   elif node["parameters"].get("respondWith") == "text":
     #             print("sure")          
     #             respond_with_text_exists = True
     #             response_body = node["parameters"].get("responseBody", "")
     #             if result == True:
     #                 if "json." in response_body:
     #                     print("shir")
     #                     response_body = remove_equals_sign(response_body)
        
     #                     payload_factory_body = create_payload_factory_inSeq(response_body)
     #                     payload_factory = ET.SubElement(in_sequence, "payloadFactory")
     #                     payload_factory.append(payload_factory_body)
     #                 elif "={\n" in response_body:
        
     #                     response_body = remove_equals_sign(response_body)
     #                     print('aaaay:', response_body)
     #                     # payload_factory_body = create_payload_factory_inSeq(response_body)
     #                     # payload_factory = ET.SubElement(in_sequence, "payloadFactory")
     #                     # payload_factory.append(payload_factory_body)


# Function to prettify XML output
def prettify(elem):
    from xml.dom import minidom
    rough_string = ET.tostring(elem, 'utf-8')
    reparsed = minidom.parseString(rough_string)
    pretty_xml = reparsed.toprettyxml(indent="  ")
    # Replace &quot; with actual double quotes
    pretty_xml = pretty_xml.replace('&quot;', '"')
    pretty_xml = pretty_xml.replace('&lt;', '<')
    pretty_xml = pretty_xml.replace('&gt;', '>')
  #  pretty_xml = pretty_xml.replace('&amp;', '&')
    print(pretty_xml)
    return pretty_xml


# Write the prettified XML to a file
output_file = "C:/Users/felodenz/Desktop/r&d/esb-code-generation-based-on-n8n-master/esb-code-generation-based-on-n8n-master/esb_config.xml"
with open(output_file, "w") as f:
    f.write(prettify(root))

print(f"ESB XML configuration saved to {output_file}")



