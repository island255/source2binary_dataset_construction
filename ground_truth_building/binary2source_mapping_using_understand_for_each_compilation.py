import json
import subprocess
import os
from binary2source_mapping_using_understand import construct_ground_truth, find_dataset_folder


def extract_dataset_info(source_dataset_dir):
    """
    get compiler options
    """
    compilation_list = []
    project_version_list = []
    compiler_version_list = []
    arch_list = []
    opt_list = []
    dataset_name = ""
    project_list = os.listdir(source_dataset_dir)
    for project in project_list:
        project_dir = os.path.join(source_dataset_dir, project)
        project_version_compiler_arch_opt_name_list = os.listdir(project_dir)
        for project_version_compiler_arch_opt_name in project_version_compiler_arch_opt_name_list:
            sub_section_list = project_version_compiler_arch_opt_name.split("_")
            if len(sub_section_list) == 6:
                project_version, compiler_version, arch, bit, opt, name = sub_section_list
                if project_version not in project_version_list:
                    project_version_list.append(project_version)
                if compiler_version not in compiler_version_list:
                    compiler_version_list.append(compiler_version)
                if arch + "_" + bit not in arch_list:
                    arch_list.append(arch + "_" + bit)
                if opt not in opt_list:
                    opt_list.append(opt)
                if dataset_name == "":
                    dataset_name = name
                compilation_list.append("_".join(sub_section_list[:-1]))

    return project_list, compilation_list, project_version_list, compiler_version_list, arch_list, opt_list, dataset_name


def split_dataset(binary_dataset_dir, source_dataset_dir,
                  project_list, dataset_name):
    dataset_per_project = {}
    for project_name in project_list:
        project_binary_dir = os.path.join(binary_dataset_dir, project_name)
        for binary_name in os.listdir(project_binary_dir):
            if "." in binary_name:
                continue
            name_part_list = binary_name.split("_")
            compilation_args = "_".join(name_part_list[:-1])
            if compilation_args not in dataset_per_project:
                dataset_per_project[compilation_args] = {}
                source_project_dir = \
                    os.path.join(os.path.join(source_dataset_dir, project_name), compilation_args + "_" + dataset_name)
                dataset_per_project[compilation_args]["source_project_dir"] = source_project_dir
                dataset_per_project[compilation_args]["binary_list"] = []
            binary_path = os.path.join(project_binary_dir, binary_name)
            dataset_per_project[compilation_args]["binary_list"].append(binary_path)
    return dataset_per_project


def use_understand_extract_entities(understand_tool, source_dir, understand_python, understand_extract_script,
                                    understand_source_entities_file):
    source_project_und = os.path.join(source_dir, "project.und")
    cmd_understand_1 = "{} create -languages C++ {}".format(understand_tool, source_project_und)
    cmd_understand_2 = "{} add {} {}".format(understand_tool, source_dir, source_project_und)
    cmd_understand_3 = "{} analyze {}".format(understand_tool, source_project_und)
    cmd = " && ".join([cmd_understand_1, cmd_understand_2, cmd_understand_3])
    ex = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    out, err  = ex.communicate()
    status = ex.wait()
    # if status

    cmd_extract_understand = "{} {} --db_path {} --result_path {}".format(understand_python, understand_extract_script,
                                                                          source_project_und, understand_source_entities_file)
    ex = subprocess.Popen(cmd_extract_understand, shell=True, stdout=subprocess.PIPE)
    out, err = ex.communicate()
    status = ex.wait()


def main():
    # dir: logs_normal output_normal sources
    # sources: project_name --> project_name: binutils-2.33.1_clang-4.0_arm_32_O0_normal
    # output_normal: project_name --> file_name: findutils-4.4.1_clang-4.0_arm_32_O0_bigram
    # "/root/IDA_Pro_6.4/idal64" -A -S"/root/extract_binary2source_mapping/extract_binary_range.py" /outside/af_netlink.o
    ida64_path = "/root/IDA_Pro_6.4/idal64"
    script_path = "/root/extract_binary2source_mapping/extract_binary_range.py"
    readelf_file_path = "readelf"
    dataset_base_dir = "/outside_dataset"
    understand_tool = "/root/scitools/bin/linux64/und"
    understand_python = "/root/scitools/bin/linux64/Python/Python-3.8/bin/python3"

    understand_extract_script = "/root/scitools/bin/linux64/Python/use_understand_to_extract_entity.py"
    ground_truth_dir = os.path.join(dataset_base_dir, "ground_truth")
    sub_dataset_folder_list = os.listdir(dataset_base_dir)
    binary_dataset_dir, source_dataset_dir = find_dataset_folder(dataset_base_dir, sub_dataset_folder_list)
    print("base_dir: {}, source_dir:{}, binary_dir:{}".format(dataset_base_dir, source_dataset_dir, binary_dataset_dir))

    project_list, compilation_list, project_version_list, compiler_version_list, arch_list, opt_list, dataset_name = \
        extract_dataset_info(source_dataset_dir)
    # dataset_per_project: source_project --> dataset_dir binary_list --> binaries
    dataset_per_project = split_dataset(binary_dataset_dir, source_dataset_dir,
                                        project_list, dataset_name)
    for compilation in dataset_per_project:
        construct_ground_truth(understand_tool, understand_extract_script, understand_python,
                               ground_truth_dir, compilation, dataset_per_project[compilation],
                               ida64_path, script_path, readelf_file_path)


if __name__ == '__main__':
    main()
