import argparse
import os
import subprocess


def test(type, round, size, log_level, name):
    env = os.environ.copy()
    env['RUST_LOG'] = log_level
    env['PATH'] = '/home/chb/.cargo/bin/:' + env['PATH']

    columns = ['order_number', 'add_to_cart_order', 'order_hour_of_day',
               'reordered', 'AGEP', 'ST', 'SPORDER', 'SEX']
    if name in columns:
        columns = [name]

    for column in columns:
        if type == 'query':
            base = 'query_' + column + '.toml'
            input_file = './test_suites/' + base
        elif type == 'attack':
            base = 'attack_' + column + '.toml'
            input_file = './test_suites/others/' + base
        else:
            raise Exception('Unrecognized option')

        output_file = './data/' + base
        command = 'cargo run --release -- -e {} -r {} -s {} -c {} -o {}'.format(type,
                                                                                round, size, input_file, output_file)

        subprocess.run(command.split(), env=env)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-r', '--round', type=int,
                        default=1, help='The test round')
    parser.add_argument('-s', '--size', type=int,
                        default=100, help='The test suite size')
    parser.add_argument('--log-level', default='info',
                        help='The log level for `RUST_LOG`')
    parser.add_argument('-n', '--name', default='all',
                        help='Which test suites you want to run')
    parser.add_argument('-t', '--type', default='perf',
                        help='Perf or attack')
    args = parser.parse_args()

    test(args.type, args.round, args.size, args.log_level, args.name)
