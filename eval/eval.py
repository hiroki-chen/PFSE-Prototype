import argparse
import os
import subprocess


def test(round, size, log_level, name):
    env = os.environ.copy()
    env['RUST_LOG'] = log_level
    env['PATH'] = '/home/chb/.cargo/bin/:' + env['PATH']

    columns = ['add_to_cart_order', 'order_hour_of_day',
               'order_dow', 'AGEP', 'SPORDER', 'CIT', 'HICOV']
    if name in columns:
        columns = [name]

    for column in columns:
        base = 'query_' + column + '.toml'
        input_file = './test_suites/' + base
        output_file = './data/' + base
        command = 'cargo run --release -- -e perf -r {} -s {} -c {} -o {}'.format(
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
    args = parser.parse_args()

    test(args.round, args.size, args.log_level, args.name)
