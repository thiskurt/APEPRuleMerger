from epo_policy import EpoPolicy
from copy import deepcopy


def main_test():
    multi = EpoPolicy('multi_policy.xml')
    split_multi(multi, '__TEST')


def split_multi(multi: EpoPolicy, path: str = 'working_directory'):
    for index, policy in enumerate(multi.defined_policies):
        copy_policy = deepcopy(multi)
        copy_policy.convert_to_single_policy(copy_policy.defined_policies[index])
        copy_policy.file.write(str(path) + '/' + str(copy_policy.policy_name) + ' (' + str(copy_policy.policy_type) + ').xml')


def convert_single(multi: EpoPolicy):
    for index, policy in enumerate(multi.defined_policies):
        print(str(index) + ') ' + policy.get('name') + ' - ' + policy.get('featureid') + ' - ' + policy.get('typeid'))
    print('\nChoose policy:\n')
    policy_id = int(input())

    multi.convert_to_single_policy(multi.defined_policies[policy_id])
    multi.file.write('test_multi_to_single.xml')


if __name__ == '__main__':
    main_test()
