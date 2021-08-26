import understand
import json
import os
import argparse


def extract_understand_entities(db_path, result_path):
    # db = understand.open("/root/project_example/coreutils/project.udb.und")
    db = understand.open(db_path)

    file_contains_entity = {}

    for entity in db.ents("file"):
        entity_relname = entity.relname()
        print(entity_relname)
        try:
            lexer_e = entity.lexer()
        except:
            print("this is not a project file")
            continue
        file_contains_entity[entity_relname] = []
        for lexemes_e in lexer_e.__iter__():
            if lexemes_e.ent():
                if lexemes_e.ent().parent() and lexemes_e.ent().parent() == entity and \
                        lexemes_e.ref().kindname() == "Define":
                    sub_entity_dict = {}
                    sub_entity = lexemes_e.ent()
                    kind = sub_entity.kind()
                    if "Function" not in kind.longname().split():
                        continue
                    begin_line = lexemes_e.line_begin()
                    total_line = lexemes_e.ent().metric(['CountLine'])['CountLine']
                    if not total_line:
                        total_line = 0
                    end_line = begin_line + total_line

                    entity_ref = {}
                    refs = sub_entity.refs("call")
                    entity_ref["call"] = []
                    for ref in refs:
                        if ref.ent().parent():
                            call_entity = ref.ent().longname()
                            call_entity_type = ref.ent().type()
                            call_entity_kind = ref.ent().kind().longname()
                            if "Function" not in call_entity_kind:
                                continue
                            call_file = ref.ent().parent().relname()
                            ref_line = ref.line()
                            entity_ref["call"].append(
                                {"file": call_file, "entity": call_entity, "type": call_entity_type,
                                 "kind": call_entity_kind, "line_number": ref_line})
                        else:
                            call_entity = ref.ent().longname()
                            call_entity_type = ref.ent().type()
                            call_entity_kind = ref.ent().kind().longname()
                            if "Function" not in call_entity_kind:
                                continue
                            call_file = ref.ent().parent()
                            ref_line = ref.line()
                            entity_ref["call"].append(
                                {"file": call_file, "entity": call_entity, "type": call_entity_type,
                                 "kind": call_entity_kind, "line_number": ref_line})
                    sub_entity_dict[sub_entity.simplename()] = {"kind": kind.longname(),
                                                                "type": sub_entity.type(),
                                                                "begin_line": str(begin_line),
                                                                "total_line": str(total_line),
                                                                "end_line": str(end_line),
                                                                "call": entity_ref["call"]}
                    file_contains_entity[entity_relname].append(sub_entity_dict)
    # print(file_contains_entity)
    # result_path = "/root/project_example/coreutils/"
    json_file = open(result_path, "w")
    json_str = json.dumps(file_contains_entity, indent=2)
    json_file.write(json_str)
    json_file.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--db_path", type=str, help="path of understand database")
    parser.add_argument("--result_path", type=str, help="path of result file")
    args = parser.parse_args()
    db_path_arg, result_path_arg = args.db_path, args.result_path
    extract_understand_entities(db_path_arg, result_path_arg)