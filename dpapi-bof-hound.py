import csv
import json
import sys

def transform_bof_output_to_og(csv_input_path, json_output_path):
    nodes = []
    edges = []
    
    # Track nodes to avoid duplicates if necessary
    node_ids = set()

    try:
        with open(csv_input_path, 'r', encoding='utf-8') as f:
            # The BOF output doesn't have headers, so we handle it manually
            for line in f:
                parts = line.strip().split(',')
                if not parts:
                    continue

                record_type = parts[0]

                if record_type == 'node':
                    # Structure: node,Type,ID,Name,...
                    kind = parts[1]
                    node_id = parts[2]
                    
                    # Ensure node is unique
                    if node_id not in node_ids:
                        node = {
                            "id": node_id,
                            "kinds": [kind],
                            "properties": {
                                "name": parts[3]
                            }
                        }
                        
                        # Add optional description if it exists (e.g., for DPAPIBlob)
                        if len(parts) > 4:
                            node["properties"]["description"] = parts[4]
                            
                        nodes.append(node)
                        node_ids.add(node_id)

                elif record_type == 'edge':
                    # Structure: edge,RelationshipType,StartNodeID,EndNodeID
                    edge = {
                        "start": {
                            "match_by": "id",
                            "value": parts[2]
                        },
                        "end": {
                            "match_by": "id",
                            "value": parts[3]
                        },
                        "kind": parts[1]
                    }
                    edges.append(edge)

        # Construct final OpenGraph structure
        og_data = {
            "metadata": {
                "source_kind": "DPAPI"
            },          
            "graph": {
                "nodes": nodes,
                "edges": edges
            }
        }

        # Write to JSON file
        with open(json_output_path, 'w', encoding='utf-8') as f:
            json.dump(og_data, f, indent=4)
        
        print(f"Successfully converted {csv_input_path} to {json_output_path}")

    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python convert.py <input_csv> <output_json>")
    else:
        transform_bof_output_to_og(sys.argv[1], sys.argv[2])