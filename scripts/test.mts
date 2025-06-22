#!/usr/bin/env zx
import 'zx/globals';
import {
  cliArguments,
  getToolchainArgument,
  workingDirectory,
} from './setup/shared.mts';

const [folder, ...args] = cliArguments();

const testArgs = ['--all-features', ...args, '--', '--nocapture'];
process.env.RUST_BACKTRACE = '1';
const toolchain = getToolchainArgument('test');

const manifestPath = path.join(workingDirectory, folder, 'Cargo.toml');

await $`cargo ${toolchain} test --manifest-path ${manifestPath} ${testArgs}`;
