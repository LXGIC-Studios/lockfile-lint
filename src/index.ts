#!/usr/bin/env node

import * as fs from "fs";
import * as path from "path";
import * as crypto from "crypto";

// ANSI colors
const c = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  dim: "\x1b[2m",
  red: "\x1b[31m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  blue: "\x1b[34m",
  magenta: "\x1b[35m",
  cyan: "\x1b[36m",
  white: "\x1b[37m",
  bgRed: "\x1b[41m",
  bgGreen: "\x1b[42m",
  bgYellow: "\x1b[43m",
};

interface LintFinding {
  severity: "error" | "warning" | "info";
  rule: string;
  message: string;
  package?: string;
  details?: string;
}

interface LintResult {
  lockfilePath: string;
  lockfileVersion: number;
  findings: LintFinding[];
  summary: {
    total: number;
    errors: number;
    warnings: number;
    info: number;
    passed: boolean;
  };
}

const HELP = `
${c.bold}${c.cyan}lockfile-lint${c.reset} - Verify package-lock.json integrity and security

${c.bold}USAGE${c.reset}
  ${c.green}npx @lxgicstudios/lockfile-lint${c.reset} [options] [path]
  ${c.green}npx @lxgicstudios/lockfile-lint${c.reset}                      ${c.dim}# check ./package-lock.json${c.reset}
  ${c.green}npx @lxgicstudios/lockfile-lint${c.reset} ./app/               ${c.dim}# check specific directory${c.reset}

${c.bold}OPTIONS${c.reset}
  --help              Show this help message
  --json              Output results as JSON
  --ci                Exit with code 1 if any errors found
  --strict            Treat warnings as errors
  --allow-registry <url>  Allow additional registries (repeatable)
  --allow-git         Allow git:// protocol dependencies
  --allow-github      Allow GitHub shorthand dependencies
  --verbose           Show all checks including passed ones

${c.bold}RULES CHECKED${c.reset}
  ${c.cyan}registry-url${c.reset}     All resolved URLs use official npm registry
  ${c.cyan}git-protocol${c.reset}     No git:// protocol (use https:// instead)
  ${c.cyan}https-only${c.reset}       All URLs use HTTPS
  ${c.cyan}integrity${c.reset}        All packages have integrity hashes
  ${c.cyan}sync-check${c.reset}       Lockfile synced with package.json
  ${c.cyan}no-file-refs${c.reset}     No file: protocol references to local paths

${c.bold}EXAMPLES${c.reset}
  ${c.dim}# Basic check${c.reset}
  npx @lxgicstudios/lockfile-lint

  ${c.dim}# CI mode (fails on errors)${c.reset}
  npx @lxgicstudios/lockfile-lint --ci

  ${c.dim}# Strict mode (warnings = errors)${c.reset}
  npx @lxgicstudios/lockfile-lint --ci --strict

  ${c.dim}# Allow a private registry${c.reset}
  npx @lxgicstudios/lockfile-lint --allow-registry https://npm.mycompany.com

  ${c.dim}# JSON output${c.reset}
  npx @lxgicstudios/lockfile-lint --json
`;

function parseArgs(argv: string[]) {
  const args = {
    help: false,
    json: false,
    ci: false,
    strict: false,
    allowRegistries: [] as string[],
    allowGit: false,
    allowGithub: false,
    verbose: false,
    target: ".",
  };

  for (let i = 2; i < argv.length; i++) {
    const arg = argv[i];
    switch (arg) {
      case "--help":
      case "-h":
        args.help = true;
        break;
      case "--json":
        args.json = true;
        break;
      case "--ci":
        args.ci = true;
        break;
      case "--strict":
        args.strict = true;
        break;
      case "--allow-registry":
        args.allowRegistries.push(argv[++i] || "");
        break;
      case "--allow-git":
        args.allowGit = true;
        break;
      case "--allow-github":
        args.allowGithub = true;
        break;
      case "--verbose":
      case "-v":
        args.verbose = true;
        break;
      default:
        if (!arg.startsWith("-")) {
          args.target = arg;
        }
        break;
    }
  }

  return args;
}

function findLockfile(target: string): string | null {
  const stat = fs.statSync(target, { throwIfNoEntry: false });
  if (!stat) return null;

  if (stat.isFile() && target.endsWith("package-lock.json")) {
    return target;
  }

  if (stat.isDirectory()) {
    const lockPath = path.join(target, "package-lock.json");
    if (fs.existsSync(lockPath)) return lockPath;
  }

  return null;
}

function findPackageJson(lockfilePath: string): string | null {
  const dir = path.dirname(lockfilePath);
  const pkgPath = path.join(dir, "package.json");
  if (fs.existsSync(pkgPath)) return pkgPath;
  return null;
}

interface LockfilePackage {
  version?: string;
  resolved?: string;
  integrity?: string;
  dependencies?: Record<string, any>;
  dev?: boolean;
  link?: boolean;
}

function checkRegistryUrls(
  packages: Record<string, LockfilePackage>,
  allowedRegistries: string[],
  findings: LintFinding[]
) {
  const officialRegistries = [
    "https://registry.npmjs.org/",
    "https://registry.yarnpkg.com/",
    ...allowedRegistries,
  ];

  for (const [name, pkg] of Object.entries(packages)) {
    if (!pkg.resolved) continue;
    if (pkg.link) continue; // Workspace links

    const isAllowed = officialRegistries.some((reg) =>
      pkg.resolved!.startsWith(reg)
    );

    if (!isAllowed) {
      findings.push({
        severity: "error",
        rule: "registry-url",
        message: `Unofficial registry URL detected`,
        package: name,
        details: `Resolved: ${pkg.resolved}`,
      });
    }
  }
}

function checkGitProtocol(
  packages: Record<string, LockfilePackage>,
  allowGit: boolean,
  allowGithub: boolean,
  findings: LintFinding[]
) {
  for (const [name, pkg] of Object.entries(packages)) {
    if (!pkg.resolved) continue;

    if (pkg.resolved.startsWith("git://") && !allowGit) {
      findings.push({
        severity: "error",
        rule: "git-protocol",
        message: `git:// protocol is insecure (no encryption)`,
        package: name,
        details: `Use git+https:// instead. Resolved: ${pkg.resolved}`,
      });
    }

    if (pkg.resolved.startsWith("git+ssh://") && !allowGit) {
      findings.push({
        severity: "warning",
        rule: "git-protocol",
        message: `git+ssh:// protocol dependency detected`,
        package: name,
        details: `Resolved: ${pkg.resolved}`,
      });
    }

    if (
      pkg.resolved.includes("github.com") &&
      !pkg.resolved.startsWith("https://registry.") &&
      !allowGithub
    ) {
      findings.push({
        severity: "warning",
        rule: "git-protocol",
        message: `GitHub direct dependency (not from npm registry)`,
        package: name,
        details: `Resolved: ${pkg.resolved}`,
      });
    }
  }
}

function checkHttpsOnly(
  packages: Record<string, LockfilePackage>,
  findings: LintFinding[]
) {
  for (const [name, pkg] of Object.entries(packages)) {
    if (!pkg.resolved) continue;
    if (pkg.link) continue;

    if (pkg.resolved.startsWith("http://")) {
      findings.push({
        severity: "error",
        rule: "https-only",
        message: `HTTP (non-encrypted) resolved URL`,
        package: name,
        details: `Resolved: ${pkg.resolved}`,
      });
    }
  }
}

function checkIntegrity(
  packages: Record<string, LockfilePackage>,
  findings: LintFinding[]
) {
  let missingCount = 0;
  const missingPackages: string[] = [];

  for (const [name, pkg] of Object.entries(packages)) {
    if (pkg.link) continue;
    if (!pkg.resolved) continue;

    if (!pkg.integrity) {
      missingCount++;
      if (missingPackages.length < 10) {
        missingPackages.push(name);
      }
    }
  }

  if (missingCount > 0) {
    findings.push({
      severity: "warning",
      rule: "integrity",
      message: `${missingCount} package(s) missing integrity hash`,
      details: `Packages: ${missingPackages.join(", ")}${missingCount > 10 ? ` and ${missingCount - 10} more` : ""}`,
    });
  }
}

function checkFileRefs(
  packages: Record<string, LockfilePackage>,
  findings: LintFinding[]
) {
  for (const [name, pkg] of Object.entries(packages)) {
    if (pkg.resolved && pkg.resolved.startsWith("file:")) {
      findings.push({
        severity: "warning",
        rule: "no-file-refs",
        message: `file: protocol reference (local path dependency)`,
        package: name,
        details: `Resolved: ${pkg.resolved}`,
      });
    }
  }
}

function checkSyncWithPackageJson(
  lockfile: any,
  packageJson: any,
  findings: LintFinding[]
) {
  const lockName = lockfile.name;
  const pkgName = packageJson.name;

  if (lockName && pkgName && lockName !== pkgName) {
    findings.push({
      severity: "error",
      rule: "sync-check",
      message: `Package name mismatch: lockfile has "${lockName}" but package.json has "${pkgName}"`,
    });
  }

  const lockVersion = lockfile.version;
  const pkgVersion = packageJson.version;

  if (lockVersion && pkgVersion && lockVersion !== pkgVersion) {
    findings.push({
      severity: "warning",
      rule: "sync-check",
      message: `Version mismatch: lockfile has "${lockVersion}" but package.json has "${pkgVersion}"`,
    });
  }

  // Check that all package.json deps exist in lockfile
  const allDeps: Record<string, string> = {
    ...(packageJson.dependencies || {}),
    ...(packageJson.devDependencies || {}),
  };

  const lockPackages = lockfile.packages || {};
  const lockDeps = lockfile.dependencies || {};

  for (const [name] of Object.entries(allDeps)) {
    // Check in lockfileVersion 3 format (packages)
    const inPackages = Object.keys(lockPackages).some(
      (key) => key === `node_modules/${name}` || key.endsWith(`/node_modules/${name}`)
    );

    // Check in lockfileVersion 1/2 format (dependencies)
    const inDeps = name in lockDeps;

    if (!inPackages && !inDeps && Object.keys(lockPackages).length > 1) {
      findings.push({
        severity: "error",
        rule: "sync-check",
        message: `"${name}" is in package.json but not in lockfile`,
        details: "Run 'npm install' to sync",
      });
    }
  }
}

function getSeverityColor(severity: string): string {
  switch (severity) {
    case "error":
      return c.red;
    case "warning":
      return c.yellow;
    case "info":
      return c.green;
    default:
      return c.reset;
  }
}

function getSeverityEmoji(severity: string): string {
  switch (severity) {
    case "error":
      return "🔴";
    case "warning":
      return "⚠️";
    case "info":
      return "✅";
    default:
      return "?";
  }
}

function main() {
  const args = parseArgs(process.argv);

  if (args.help) {
    console.log(HELP);
    process.exit(0);
  }

  const lockfilePath = findLockfile(args.target);
  if (!lockfilePath) {
    console.error(
      `${c.red}Error:${c.reset} No package-lock.json found in ${args.target}`
    );
    process.exit(1);
  }

  let lockfile: any;
  try {
    lockfile = JSON.parse(fs.readFileSync(lockfilePath, "utf-8"));
  } catch (err: any) {
    console.error(
      `${c.red}Error:${c.reset} Failed to parse ${lockfilePath}: ${err.message}`
    );
    process.exit(1);
  }

  const lockfileVersion = lockfile.lockfileVersion || 1;

  if (!args.json) {
    console.log(
      `\n${c.bold}${c.cyan}lockfile-lint${c.reset} ${c.dim}Checking ${lockfilePath} (v${lockfileVersion})...${c.reset}\n`
    );
  }

  const findings: LintFinding[] = [];

  // Get packages based on lockfile version
  let packages: Record<string, LockfilePackage> = {};

  if (lockfileVersion >= 2 && lockfile.packages) {
    // v2/v3 format
    packages = { ...lockfile.packages };
    // Remove root entry
    delete packages[""];
  } else if (lockfile.dependencies) {
    // v1 format
    packages = flattenV1Dependencies(lockfile.dependencies);
  }

  const packageCount = Object.keys(packages).length;

  // Run all checks
  checkRegistryUrls(packages, args.allowRegistries, findings);
  checkGitProtocol(packages, args.allowGit, args.allowGithub, findings);
  checkHttpsOnly(packages, findings);
  checkIntegrity(packages, findings);
  checkFileRefs(packages, findings);

  // Check sync with package.json
  const pkgJsonPath = findPackageJson(lockfilePath);
  if (pkgJsonPath) {
    try {
      const packageJson = JSON.parse(fs.readFileSync(pkgJsonPath, "utf-8"));
      checkSyncWithPackageJson(lockfile, packageJson, findings);
    } catch {
      findings.push({
        severity: "warning",
        rule: "sync-check",
        message: "Could not parse package.json for sync check",
      });
    }
  }

  // Lockfile version check
  if (lockfileVersion < 2) {
    findings.push({
      severity: "info",
      rule: "lockfile-version",
      message: `Lockfile version ${lockfileVersion} detected. Consider upgrading to v3 (npm 7+)`,
    });
  }

  // Apply strict mode
  if (args.strict) {
    for (const finding of findings) {
      if (finding.severity === "warning") {
        finding.severity = "error";
      }
    }
  }

  // Build result
  const result: LintResult = {
    lockfilePath,
    lockfileVersion,
    findings,
    summary: {
      total: findings.length,
      errors: findings.filter((f) => f.severity === "error").length,
      warnings: findings.filter((f) => f.severity === "warning").length,
      info: findings.filter((f) => f.severity === "info").length,
      passed: findings.filter((f) => f.severity === "error").length === 0,
    },
  };

  if (args.json) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    if (findings.length === 0) {
      console.log(`  ${c.green}${c.bold}All checks passed!${c.reset} ✅`);
      console.log(
        `  ${c.dim}Scanned ${packageCount} packages in ${lockfilePath}${c.reset}\n`
      );
    } else {
      // Group by rule
      const byRule = new Map<string, LintFinding[]>();
      for (const finding of findings) {
        const arr = byRule.get(finding.rule) || [];
        arr.push(finding);
        byRule.set(finding.rule, arr);
      }

      for (const [rule, ruleFindings] of byRule) {
        console.log(`  ${c.bold}${rule}${c.reset}`);
        for (const finding of ruleFindings) {
          const sevColor = getSeverityColor(finding.severity);
          const emoji = getSeverityEmoji(finding.severity);
          console.log(
            `    ${emoji} ${sevColor}${finding.severity}${c.reset}: ${finding.message}`
          );
          if (finding.package) {
            console.log(`       ${c.dim}Package: ${finding.package}${c.reset}`);
          }
          if (finding.details && args.verbose) {
            console.log(`       ${c.dim}${finding.details}${c.reset}`);
          }
        }
        console.log();
      }

      console.log(`${c.bold}${"─".repeat(50)}${c.reset}`);
      console.log(`${c.bold}Summary${c.reset} - ${packageCount} packages checked`);
      console.log(
        `  ${c.red}Errors: ${result.summary.errors}${c.reset}  ` +
          `${c.yellow}Warnings: ${result.summary.warnings}${c.reset}  ` +
          `${c.green}Info: ${result.summary.info}${c.reset}`
      );

      if (result.summary.passed) {
        console.log(`  ${c.green}${c.bold}PASSED${c.reset} (no errors)\n`);
      } else {
        console.log(`  ${c.red}${c.bold}FAILED${c.reset} (${result.summary.errors} error(s))\n`);
      }
    }
  }

  // CI exit code
  if (args.ci && !result.summary.passed) {
    process.exit(1);
  }
}

function flattenV1Dependencies(
  deps: Record<string, any>,
  prefix: string = ""
): Record<string, LockfilePackage> {
  const flat: Record<string, LockfilePackage> = {};

  for (const [name, data] of Object.entries(deps)) {
    const key = prefix ? `${prefix}/node_modules/${name}` : `node_modules/${name}`;
    flat[key] = {
      version: data.version,
      resolved: data.resolved,
      integrity: data.integrity,
      dev: data.dev,
    };

    if (data.dependencies) {
      Object.assign(flat, flattenV1Dependencies(data.dependencies, key));
    }
  }

  return flat;
}

main();
