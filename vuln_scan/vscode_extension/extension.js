const vscode = require('vscode');
const { exec } = require('child_process');
function activate(context) {
    let disposable = vscode.commands.registerCommand('vuln-scan.scanFile', function () {
        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            vscode.window.showInformationMessage('Open a file to scan first.');
            return;
        }
        const path = editor.document.fileName;
        vscode.window.showInformationMessage('Scanning: ' + path);
        // call CLI (ensure env is set)
        exec(`python -u bin/cli.py "${path}"`, {cwd: vscode.workspace.rootPath}, (err, stdout, stderr) => {
            if (err) {
                vscode.window.showErrorMessage('Scan error: ' + err.message);
                return;
            }
            vscode.window.showInformationMessage('Scan complete. Check output console.');
            console.log(stdout);
        });
    });
    context.subscriptions.push(disposable);
}
exports.activate = activate;
function deactivate() {}
exports.deactivate = deactivate;
