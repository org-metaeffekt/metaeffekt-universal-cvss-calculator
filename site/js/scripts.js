/*
 * Copyright 2024 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
class CvssVectorRepresentation {

    constructor(name, cvssInstance, shown) {
        this.initialCvssInstance = cvssInstance.clone();
        this.cvssInstance = cvssInstance;
        this.name = name;
        this.shown = shown === undefined ? true : shown;
        this.hasBeenDestroyed = false;

        const [domElement, scoreDisplayButton, nameElement, vectorStringElement, copyVectorToClipboardButton, visibilityToggleButton, removeButton] = this.createDomElement();
        this.domElement = domElement;
        this.scoreDisplayButton = scoreDisplayButton;
        this.nameElement = nameElement;
        this.vectorStringElement = vectorStringElement;
        this.copyVectorToClipboardButton = copyVectorToClipboardButton;
        this.visibilityToggleButton = visibilityToggleButton;
        this.removeButton = removeButton;

        this.cvssInstance.addVectorChangedListener(vector => {
            if (this.hasBeenDestroyed) {
                return;
            }
            this.vectorStringElement.value = vector.toString();
            if (selectedVector === this.cvssInstance) {
                setSelectedVector(vector);
            }
            updateScores();
            storeInGet();
        });

        // on finish editing the vector string, update the cvss instance
        this.vectorStringElement.addEventListener('change', () => {
            if (this.vectorStringElement.value !== this.cvssInstance.toString()) {
                try {
                    const parsedVector = createInstanceForVector(this.vectorStringElement.value);
                    if (parsedVector.constructor !== this.cvssInstance.constructor) {
                        createBootstrapToast('Version mismatch', 'Vector version and provided version do not match', 'warning');
                        this.vectorStringElement.value = this.cvssInstance.toString();
                        return;
                    }
                } catch (e) {
                    createBootstrapToast('Invalid CVSS vector', 'Please enter a valid CVSS vector', 'error');
                    this.vectorStringElement.value = this.cvssInstance.toString();
                    return;
                }
                this.cvssInstance.clearComponents();
                this.cvssInstance.applyVector(this.vectorStringElement.value);
            } else {
                createBootstrapToast('No change', 'The vector string has not changed', 'warning');
                this.vectorStringElement.value = this.cvssInstance.toString();
            }
        });

        // clicking the copy button will copy the vector string to the clipboard
        this.copyVectorToClipboardButton.addEventListener('click', event => {
            if (this.hasBeenDestroyed) {
                return;
            }
            if (event.altKey || event.metaKey || event.ctrlKey || event.shiftKey) {
                const diffVector = this.cvssInstance.diffVector(this.initialCvssInstance);
                const diffVectorString = diffVector.toString(false, diffVector.getRegisteredComponents(), true);
                if (diffVector && diffVector.size() > 0) {
                    copyText(diffVectorString, 'diff vector with ' + diffVector.size() + ' changes');
                    this.vectorStringElement.value = diffVectorString;
                    setTimeout(() => {
                        this.vectorStringElement.value = this.cvssInstance.toString();
                    }, 1700);
                } else {
                    createBootstrapToast('No change', 'The vector string has not changed from it\'s initial state. Use the buttons below to change some components first.', 'warning');
                    this.vectorStringElement.value = 'No changes';
                    setTimeout(() => {
                        this.vectorStringElement.value = this.cvssInstance.toString();
                    }, 1200);
                }
            } else {
                copyText(this.vectorStringElement.value, 'vector');
            }
        });

        this.nameElement.addEventListener('change', () => {
            this.name = this.nameElement.value;
            this.adjustNameColumnSize();
            updateScores();
            storeInGet();
        });

        // remove button
        this.removeButton.addEventListener('click', () => {
            if (this.hasBeenDestroyed) {
                return;
            }
            this.hasBeenDestroyed = true;
            this.domElement.remove();
            const index = cvssVectors.indexOf(this);
            if (index > -1) {
                cvssVectors.splice(index, 1);
            }
            this.adjustNameColumnSize();
            if (selectedVector === this.cvssInstance) {
                setSelectedVector(null);
            }
            updateScores();
            storeInGet();
            unregisterAllTooltips(this.domElement);
        });

        this.visibilityToggleButton.addEventListener('click', () => {
            if (this.hasBeenDestroyed) {
                return;
            }
            this.shown = !this.shown;
            updateScores();
            storeInGet();
        });

        // add global selection listener
        this.domElement.addEventListener('click', () => {
            if (this.hasBeenDestroyed) {
                return;
            }
            setSelectedVector(this.cvssInstance);
        });

        storeInGet();
    }

    appendTo(container) {
        container.appendChild(this.domElement);
    }

    createDomElement() {
        const domElement = document.createElement('div');
        domElement.classList.add('btn-group', 'w-100', 'd-flex');
        domElement.setAttribute('role', 'group');

        const scoreDisplayButton = document.createElement('button');
        {
            scoreDisplayButton.type = 'button';
            scoreDisplayButton.classList.add('btn');
            scoreDisplayButton.style.width = '4rem';
            domElement.appendChild(scoreDisplayButton);
        }

        const nameElement = document.createElement('input');
        {
            nameElement.type = 'text';
            nameElement.classList.add('btn', 'button-no-break', 'cvss-vector-name');
            if (this.cvssInstance instanceof CvssCalculator.Cvss2) {
                nameElement.classList.add('bg-cvss-2');
            } else if (this.cvssInstance instanceof CvssCalculator.Cvss3P1) {
                nameElement.classList.add('bg-cvss-3P1');
            } else if (this.cvssInstance instanceof CvssCalculator.Cvss4P0) {
                nameElement.classList.add('bg-cvss-4P0');
            }
            // nameElement.size = 20;
            nameElement.value = this.name;
            // nameElement.readOnly = true;
            domElement.appendChild(nameElement);
        }

        const vectorStringElement = document.createElement('input');
        {
            vectorStringElement.type = 'text';
            vectorStringElement.classList.add('btn', 'btn-outline-secondary', 'w-100', 'font-monospace', 'text-start', 'scrollable-content', 'cvss-vector-string');
            vectorStringElement.value = this.cvssInstance.toString();
            domElement.appendChild(vectorStringElement);
        }

        const copyVectorToClipboardButton = document.createElement('button');
        {
            copyVectorToClipboardButton.type = 'button';
            copyVectorToClipboardButton.classList.add('btn', 'btn-outline-secondary', 'cvss-vector-button-copy-to-clipboard');
            copyVectorToClipboardButton.setAttribute('data-bs-toggle', 'popover');
            copyVectorToClipboardButton.setAttribute('data-bs-placement', 'left');
            copyVectorToClipboardButton.setAttribute('data-bs-content', 'Copy vector to clipboard. Shift + click to copy only components that changed since adding them to this page.');
            copyVectorToClipboardButton.setAttribute('data-bs-trigger', 'hover');
            const copyIcon = document.createElement('i');
            copyIcon.classList.add('bi', 'bi-clipboard');
            copyVectorToClipboardButton.appendChild(copyIcon);
            domElement.appendChild(copyVectorToClipboardButton);
        }

        const visibilityToggleButton = document.createElement('button');
        {
            visibilityToggleButton.type = 'button';
            visibilityToggleButton.classList.add('btn', 'btn-outline-secondary', 'cvss-vector-button-toggle-visibility');
            visibilityToggleButton.setAttribute('data-bs-toggle', 'popover');
            visibilityToggleButton.setAttribute('data-bs-placement', 'bottom');
            visibilityToggleButton.setAttribute('data-bs-content', 'Toggle visibility');
            visibilityToggleButton.setAttribute('data-bs-trigger', 'hover');
            const visibilityIcon = document.createElement('i');
            visibilityIcon.classList.add('bi', 'bi-eye');
            visibilityToggleButton.appendChild(visibilityIcon);
            domElement.appendChild(visibilityToggleButton);
        }

        const removeButton = document.createElement('button');
        {
            removeButton.type = 'button';
            removeButton.classList.add('btn', 'btn-outline-danger', 'cvss-vector-button-remove');
            removeButton.setAttribute('data-bs-toggle', 'popover');
            removeButton.setAttribute('data-bs-placement', 'right');
            removeButton.setAttribute('data-bs-content', 'Remove vector');
            removeButton.setAttribute('data-bs-trigger', 'hover');
            const removeIcon = document.createElement('i');
            removeIcon.classList.add('bi', 'bi-dash-circle');
            removeButton.appendChild(removeIcon);
            domElement.appendChild(removeButton);
        }

        updateTooltip(domElement);

        return [domElement, scoreDisplayButton, nameElement, vectorStringElement, copyVectorToClipboardButton, visibilityToggleButton, removeButton];
    }

    findRealRenderedTextWidthWithFontOfElement(referenceElement, text) {
        const tempElement = document.createElement('span');
        tempElement.style.visibility = 'hidden';
        tempElement.style.position = 'absolute';
        tempElement.style.whiteSpace = 'nowrap';

        // copy font styles from the reference element
        const computedStyle = window.getComputedStyle(referenceElement);
        tempElement.style.fontSize = computedStyle.fontSize;
        tempElement.style.fontFamily = computedStyle.fontFamily;
        tempElement.style.fontWeight = computedStyle.fontWeight;
        tempElement.style.fontStyle = computedStyle.fontStyle;
        tempElement.style.letterSpacing = computedStyle.letterSpacing;

        tempElement.textContent = text;
        document.body.appendChild(tempElement);

        const width = tempElement.offsetWidth;

        document.body.removeChild(tempElement);

        return width;
    }

    adjustNameColumnSize() {
        let maxNameLength = 0;
        let maxLengthName = '';
        for (let vector of cvssVectors) {
            if (maxNameLength < vector.name.length) {
                maxNameLength = vector.name.length;
                maxLengthName = vector.name;
            }
        }

        const actualWidth = this.findRealRenderedTextWidthWithFontOfElement(this.nameElement, maxLengthName);
        const targetSize = actualWidth / (actualWidth < 100 ? 6 : (actualWidth < 165 ? 5.2 : (actualWidth < 270 ? 5 : (actualWidth < 320 ? 4.4 : (actualWidth < 380 ? 4 : (3))))));
        for (let vector of cvssVectors) {
            vector.nameElement.size = targetSize;
        }
    }
}

function constructRadarChartInstance(canvasId) {
    const severityRadarCtx = document.getElementById(canvasId).getContext('2d');
    return new Chart(severityRadarCtx, {
        type: 'radar',
        data: {
            labels: ['Base', 'Adj. Impact', 'Impact', 'Temporal', 'Exploitability', 'Environmental'],
            datasets: []
        },
        options: {
            animation: false,
            elements: {
                line: {
                    borderWidth: 3
                }
            },
            scales: {
                r: {
                    angleLines: {
                        display: false
                    },
                    suggestedMin: 0,
                    suggestedMax: 10,
                    ticks: {
                        stepSize: 2
                    }
                }
            }
        }
    });
}

function appendRadarChartToContainer(container, name) {
    const card = document.createElement('div');
    card.classList.add('card');
    card.classList.add('mb-3');
    card.id = name + 'SeverityRadarContainer';

    container.insertBefore(card, insertAdditionalRadarChartsBeforeThis);

    const cardHeader = document.createElement('div');
    cardHeader.classList.add('card-header', 'd-flex', 'justify-content-between', 'align-items-center');
    cardHeader.innerText = name;
    card.appendChild(cardHeader);

    const cardBody = document.createElement('div');
    cardBody.classList.add('card-body');
    card.appendChild(cardBody);

    const canvas = document.createElement('canvas');
    canvas.id = name + 'SeverityRadar';
    cardBody.appendChild(canvas);
}

const cvssVersionConstructors = {
    '2.0': CvssCalculator.Cvss2,
    '3.1': CvssCalculator.Cvss3P1,
    '4.0': CvssCalculator.Cvss4P0,
    'CVSS:2.0': CvssCalculator.Cvss2,
    'CVSS:3.1': CvssCalculator.Cvss3P1,
    'CVSS:4.0': CvssCalculator.Cvss4P0
}

const cvssVectorListContainerElement = document.getElementById('cvss-vector-list');
const cvssComponentsContainerElement = document.getElementById('cvss-component-details');
const cvssScoreDetailsContainerElement = document.getElementById('cvss-score-details');
const additionalRadarChartContainer = document.getElementById('additionalRadarChartContainer');
const severityRadarToggleContainer = document.getElementById('severityRadarToggleContainer');
const cvss4MacroVectorExplanationCard = document.getElementById('cvss4MacroVectorExplanationCard');
const cvss4MacroVectorExplanation = document.getElementById('cvss4MacroVectorExplanation');
const cveDetailsDisplay = document.getElementById('cveDetailsDisplay');
const cveDetailsDisplayCard = document.getElementById('cveDetailsDisplayCard');
const cveDetailsDisplayTitle = document.getElementById('cveDetailsDisplayTitle');
const selectedCvssDuplicatedSection = document.getElementById('selected-cvss-duplicated-section');
const insertAdditionalRadarChartsBeforeThis = document.getElementById('insert-additional-radar-charts-before-this');
cvssComponentsContainerElement.innerText = '';
cvssScoreDetailsContainerElement.innerText = '';

appendRadarChartToContainer(additionalRadarChartContainer, 'CVSS:4.0');
appendRadarChartToContainer(additionalRadarChartContainer, 'CVSS:3.1');
appendRadarChartToContainer(additionalRadarChartContainer, 'CVSS:2.0');
const defaultSeverityRadarChart = constructRadarChartInstance('defaultSeverityRadar');
const cvss4P0SeverityRadarChart = constructRadarChartInstance('CVSS:4.0SeverityRadar');
const cvss3P1SeverityRadarChart = constructRadarChartInstance('CVSS:3.1SeverityRadar');
const cvss2P0SeverityRadarChart = constructRadarChartInstance('CVSS:2.0SeverityRadar');

const defaultSeverityRadarContainer = document.getElementById('defaultSeverityRadarContainer');
const cvss4P0SeverityRadarContainer = document.getElementById('CVSS:4.0SeverityRadarContainer');
const cvss3P1SeverityRadarContainer = document.getElementById('CVSS:3.1SeverityRadarContainer');
const cvss2P0SeverityRadarContainer = document.getElementById('CVSS:2.0SeverityRadarContainer');

const cvssVectors = [];

severityRadarToggleContainer.addEventListener('click', () => {
    updateScores();
});

function createInstanceForVector(vectorInput, forceVersion = undefined) {
    if (forceVersion) {
        const vectorClass = cvssVersionConstructors[forceVersion];
        if (vectorClass) {
            return new vectorClass(vectorInput);
        }
    }
    if (typeof vectorInput === 'string') {
        const vectorClass = cvssVersionConstructors[vectorInput];
        if (vectorClass) {
            return new vectorClass();
        }
        // assume that it is a vector string
        for (let versionName in cvssVersionConstructors) {
            const specificVectorClass = cvssVersionConstructors[versionName];
            try {
                return new specificVectorClass(vectorInput);
            } catch (e) {
            }
        }
        return null;
    } else if (vectorInput instanceof Function) {
        return new vectorInput()
    } else {
        return null;
    }
}

function appendNewVector(vectorInput, name, shown = true, version = undefined) {
    const cvssInstance = createInstanceForVector(vectorInput, version);
    if (cvssInstance) {
        if (!name) {
            name = cvssInstance.getVectorName()
            const screenWidth = window.innerWidth;
            if (screenWidth < 992) {
                name = name.replace('CVSS:', '');
            }
        }
        const vectorRepresentation = new CvssVectorRepresentation(name, cvssInstance, shown);
        vectorRepresentation.appendTo(cvssVectorListContainerElement);
        cvssVectors.push(vectorRepresentation);
        vectorRepresentation.adjustNameColumnSize();
        updateScores();
        return true;
    } else {
        invalidVectorToast(vectorInput, name);
        return false;
    }
}

function appendNewEmptyVector(vectorInput, name, prependCvssOnLargeScreens = false) {
    const screenWidth = window.innerWidth;
    if (screenWidth >= 992 && prependCvssOnLargeScreens) {
        name = 'CVSS:' + name;
    }

    let cvssInstance;
    try {
        cvssInstance = createInstanceForVector(vectorInput);
    } catch (e) {
        invalidVectorToast(vectorInput, name);
        return;
    }
    if (cvssInstance) {
        cvssInstance.fillRandomBaseVector();
        const vectorRepresentation = new CvssVectorRepresentation(name, cvssInstance);
        vectorRepresentation.appendTo(cvssVectorListContainerElement);
        cvssVectors.push(vectorRepresentation);
        vectorRepresentation.adjustNameColumnSize();
        updateScores();
        setSelectedVector(cvssInstance);
    } else {
        invalidVectorToast(vectorInput, name);
    }
}

function invalidVectorToast(vectorInput, name) {
    if (name) {
        createBootstrapToast('Invalid CVSS vector', vectorInput + ' is not a valid CVSS vector for ' + name, 'error');
    } else {
        createBootstrapToast('Invalid CVSS vector', vectorInput + ' is not a valid CVSS vector', 'error');
    }
}

function clearVectors() {
    while (cvssVectors.length > 0) {
        cvssVectors.pop().removeButton.click();
    }
}

let isCurrentlyFetchingFromVulnerability = false;

function appendVectorByVulnerabilityOrVector(vulnOrVector, completionCallback = undefined) {
    if (!vulnOrVector) {
        return;
    }
    const vulnerability = extractAndFormatCVE(vulnOrVector.toUpperCase());
    if (!vulnerability || vulnerability.length === 0 || !vulnerability.startsWith('CVE-')) {
        appendNewVector(vulnOrVector, undefined, true);
        const inputElement = document.getElementById('inputAddVectorByVulnerability');
        inputElement.value = '';
    } else {
        appendVectorByVulnerability(vulnerability, completionCallback);
    }
}

function appendVectorByVulnerability(vulnerability, completionCallback = undefined) {
    if (!vulnerability) {
        return;
    }
    vulnerability = extractAndFormatCVE(vulnerability.toUpperCase());
    if (vulnerability.length === 0 || !vulnerability.startsWith('CVE-')) {
        createBootstrapToast('Invalid input', 'Please enter a valid CVE identifier', 'warning');
        return;
    }
    if (isCurrentlyFetchingFromVulnerability) {
        createBootstrapToast('Already fetching', 'Please wait until the previous request has finished', 'warning');
        return;
    }

    const inputElement = document.getElementById('inputAddVectorByVulnerability');
    inputElement.setAttribute('disabled', 'disabled')

    isCurrentlyFetchingFromVulnerability = true;
    const inputAddVectorByString = document.getElementById('inputAddVectorByString');
    inputAddVectorByString.classList.remove('btn-success');
    inputAddVectorByString.classList.add('btn-secondary');

    const inputLabelPreviousContent = inputAddVectorByString.innerHTML;
    inputAddVectorByString.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> &nbsp;NVD';

    fetchVulnerabilityData(vulnerability)
        .then(json => {
            inputElement.removeAttribute('disabled');
            isCurrentlyFetchingFromVulnerability = false;
            const cvssVectors = extractCvssVectors(json);
            const englishDescription = extractEnglishDescription(vulnerability, json);

            inputAddVectorByString.classList.remove('btn-secondary');
            inputAddVectorByString.innerHTML = inputLabelPreviousContent;

            if (cvssVectors.length === 0) {
                createBootstrapToast('Error fetching from NVD', 'No CVSS vector found for ' + vulnerability, 'error');
                inputAddVectorByString.classList.remove('btn-success');
                inputAddVectorByString.classList.add('btn-danger');
                return;
            }
            inputAddVectorByString.classList.remove('btn-danger');
            inputAddVectorByString.classList.add('btn-success');

            inputElement.value = '';

            for (let cvssVector of cvssVectors) {
                let name = vulnerability.replace('CVE-', '');
                if (cvssVector.source) {
                    // security-advisories@github.com --> github.com
                    let source = cvssVector.source.replace(/.*@/, '');
                    name += ' (' + source + ')';
                }
                if (cvssVector.version) {
                    name = cvssVector.version + ' ' + name;
                }
                appendNewVector(cvssVector.vector, name, true, cvssVector.version);
            }

            completionCallback && completionCallback();
        })
        .catch(error => {
            isCurrentlyFetchingFromVulnerability = false;
            inputElement.removeAttribute('disabled');
            inputAddVectorByString.classList.remove('btn-secondary');
            inputAddVectorByString.classList.remove('btn-success');
            inputAddVectorByString.classList.add('btn-danger');
            inputAddVectorByString.innerHTML = inputLabelPreviousContent;
            createBootstrapToast('Error fetching from NVD', 'Error fetching data: ' + error, 'error');
            completionCallback && completionCallback();
        });
}

function capitalizeFirstLetter(string) {
    if (string.length === 0) {
        return string;
    }
    return string.charAt(0).toUpperCase() + string.slice(1);
}

function interpolateChartScores(scores) {
    if (isNotDefined(scores.environmental) && scores.base && scores.exploitability) {
        scores.environmental = createInterpolationPoint(scores.base, scores.exploitability);
    }
    if (isNotDefined(scores.modifiedImpact) && scores.base && scores.impact) {
        scores.modifiedImpact = createInterpolationPoint(scores.base, scores.impact);
    }
    if (isNotDefined(scores.temporal) && scores.exploitability && scores.impact) {
        scores.temporal = createInterpolationPoint(scores.exploitability, scores.impact);
    }
}

function isNotDefined(value) {
    return value === undefined || value === null || isNaN(value);
}

function createInterpolationPoint(leftScore, rightScore) {
    let leftPosition = [0, leftScore];
    let rightPosition = [0, rightScore];
    rightPosition = rotateVector(rightPosition, 90 + 90 / 3);

    let interSectionLineInnerPosition = [0, 0];
    let interSectionLineOuterPosition = rotateVector([0, 1], (90 / 3) * 2);

    // find intersection of the two lines
    const interSectionPoint = intersectionPoint([leftPosition, rightPosition], [interSectionLineInnerPosition, interSectionLineOuterPosition]);
    return distance([0, 0], interSectionPoint);
}

function rotateVector(vector, degrees) {
    const radians = degrees * Math.PI / 180;
    const cos = Math.cos(radians);
    const sin = Math.sin(radians);
    const x = vector[0] * cos - vector[1] * sin;
    const y = vector[0] * sin + vector[1] * cos;
    return [x, y];
}

function intersectionPoint(line1, line2) {
    const x1 = line1[0][0];
    const y1 = line1[0][1];
    const x2 = line1[1][0];
    const y2 = line1[1][1];
    const x3 = line2[0][0];
    const y3 = line2[0][1];
    const x4 = line2[1][0];
    const y4 = line2[1][1];
    const x = ((x1 * y2 - y1 * x2) * (x3 - x4) - (x1 - x2) * (x3 * y4 - y3 * x4))
        / ((x1 - x2) * (y3 - y4) - (y1 - y2) * (x3 - x4));
    const y = ((x1 * y2 - y1 * x2) * (y3 - y4) - (y1 - y2) * (x3 * y4 - y3 * x4))
        / ((x1 - x2) * (y3 - y4) - (y1 - y2) * (x3 - x4));
    return [x, y];
}

function distance(point1, point2) {
    const x1 = point1[0];
    const y1 = point1[1];
    const x2 = point2[0];
    const y2 = point2[1];
    return Math.sqrt(Math.pow(x1 - x2, 2) + Math.pow(y1 - y2, 2));
}

let updateScoreDebounceTimeout = null;

function updateScores() {
    if (updateScoreDebounceTimeout) {
        clearTimeout(updateScoreDebounceTimeout);
    }
    updateScoreDebounceTimeout = setTimeout(() => {
        if (cvssVectors.length > 25) {
            const removeCount = cvssVectors.length - 25;
            while (cvssVectors.length > 25) {
                cvssVectors.pop().removeButton.click();
            }
            createBootstrapToast('Too many vectors', removeCount + ' ' + (removeCount === 1 ? 'vector has' : 'vectors have') + ' been removed from your list.', 'warning');
        }

        const shownVectors = cvssVectors.filter(vector => vector.shown);
        const hiddenVectors = cvssVectors.filter(vector => !vector.shown);
        const selectedVectorContainerInstance = cvssVectors.find(vector => vector.cvssInstance === selectedVector);

        for (let vector of hiddenVectors) {
            vector.visibilityToggleButton.classList.remove('btn-outline-secondary');
            vector.visibilityToggleButton.classList.add('btn-secondary');
        }
        for (let vector of shownVectors) {
            vector.visibilityToggleButton.classList.remove('btn-secondary');
            vector.visibilityToggleButton.classList.add('btn-outline-secondary');
        }

        // tutorial elements
        const showOnlyIfNoVectorPresent = document.getElementsByClassName('only-if-no-vectors-present');
        const showOnlyIfVectorPresent = document.getElementsByClassName('only-if-vectors-present');
        if (cvssVectors.length > 0) {
            for (let element of showOnlyIfNoVectorPresent) {
                element.classList.add('d-none');
            }
            for (let element of showOnlyIfVectorPresent) {
                element.classList.remove('d-none');
            }
        } else {
            for (let element of showOnlyIfNoVectorPresent) {
                element.classList.remove('d-none');
            }
            for (let element of showOnlyIfVectorPresent) {
                element.classList.add('d-none');
            }
        }


        // cve description display
        if (selectedVectorContainerInstance) {
            const vulnerabilityName = extractAndFormatCVE(selectedVectorContainerInstance.name);
            let description = getCachedDescription(vulnerabilityName);

            if (!description) {
                fetchVulnerabilityData(vulnerabilityName)
                    .then(json => {
                        description = extractEnglishDescription(vulnerabilityName, json);
                        if (description) {
                            cveDetailsDisplayTitle.innerText = vulnerabilityName;
                            cveDetailsDisplay.innerText = description;
                            cveDetailsDisplayTitle.href = 'https://nvd.nist.gov/vuln/detail/' + vulnerabilityName;
                            cveDetailsDisplayCard.classList.remove('d-none');
                        } else {
                            cveDetailsDisplayCard.classList.add('d-none');
                        }
                    })
            }

            if (description) {
                cveDetailsDisplayTitle.innerText = vulnerabilityName;
                cveDetailsDisplay.innerText = description;
                cveDetailsDisplayTitle.href = 'https://nvd.nist.gov/vuln/detail/' + vulnerabilityName;
                cveDetailsDisplayCard.classList.remove('d-none');
            } else {
                cveDetailsDisplayCard.classList.add('d-none');
            }
        } else {
            cveDetailsDisplayCard.classList.add('d-none');
        }

        const datasets = {'default': [], 'CVSS:2.0': [], 'CVSS:3.1': [], 'CVSS:4.0': []};
        const useVersionedCharts = !document.getElementById('severityRadarToggle').checked;

        for (let vector of cvssVectors) {
            const scores = vector.cvssInstance.calculateScores(true);
            const vectorName = vector.cvssInstance.getVectorName();

            if (vector.cvssInstance instanceof CvssCalculator.Cvss4P0) {
                scores.base = scores.overall;
                scores.impact = scores.overall;
                scores.exploitability = scores.overall;
                scores.modifiedImpact = scores.overall;
                scores.temporal = scores.overall;
                scores.environmental = scores.overall;
            }

            if (!isNotDefined(scores.overall)) {
                const severityRange = severityRangeColorFinder(scores.overall);
                vector.scoreDisplayButton.classList.remove('bg-pastel-gray', 'bg-strong-yellow', 'bg-strong-light-orange', 'bg-strong-dark-orange', 'bg-strong-red');
                vector.scoreDisplayButton.classList.add('bg-' + severityRange.color);
                vector.scoreDisplayButton.setAttribute('data-bs-toggle', 'popover');
                vector.scoreDisplayButton.setAttribute('data-bs-placement', 'left');
                vector.scoreDisplayButton.setAttribute('data-bs-content', severityRange.severity);
                vector.scoreDisplayButton.setAttribute('data-bs-trigger', 'hover');

                if (scores.overall === 0 && !vector.cvssInstance.isBaseFullyDefined()) {
                    vector.scoreDisplayButton.innerHTML = '<i class="bi bi-exclamation-triangle-fill"></i>';
                    vector.scoreDisplayButton.setAttribute('data-bs-content', 'All base metrics must be defined to calculate CVSS scores.');
                } else if (scores.overall !== 10) {
                    vector.scoreDisplayButton.innerText = scores.overall.toFixed(1);
                } else {
                    vector.scoreDisplayButton.innerText = '10';
                }

                unregisterAllTooltips(vector.scoreDisplayButton.parentElement);
                updateTooltip(vector.scoreDisplayButton.parentElement);
            }

            // chart
            const isPointDefined = [scores.base, scores.modifiedImpact, scores.impact, scores.temporal, scores.exploitability, scores.environmental].map(v => isNaN(v) ? 0 : 3);

            interpolateChartScores(scores);

            let color = [180, 48, 52];
            if (vectorName === 'CVSS:2.0') {
                color = [347, 100, 69];
            } else if (vectorName === 'CVSS:3.1') {
                color = [204, 82, 57];
            } else if (vectorName === 'CVSS:4.0') {
                color = [57, 72, 54];
            }

            // modify the color a bit randomly seeded based on the vector.getName() to make it more distinguishable
            let seed = vector.name.split('').reduce((acc, cur) => acc + cur.charCodeAt(0), 0);
            seed += 1;
            seed = seed % 30;
            if (seed % 2 === 0) seed *= -1;
            color[0] = (color[0] + seed) % 360;

            const dataset = {
                label: vector.name,
                data: [scores.base, scores.modifiedImpact, scores.impact, scores.temporal, scores.exploitability, scores.environmental],
                backgroundColor: `hsla(${color[0]},${color[1]}%,${color[2]}%,0.1)`,
                borderColor: `hsl(${color[0]},${color[1]}%,${color[2]}%)`,
                pointRadius: isPointDefined,
                /* hide when not shown */
                hidden: !vector.shown
            };
            if (selectedVector === vector.cvssInstance) {
                dataset.borderWidth = 4;
                // dataset.pointStyle = 'triangle';
                dataset.borderDash = [20, 3];
            }
            datasets['default'].push(dataset);
            if (!datasets[vectorName]) {
                datasets[vectorName] = [];
            }
            datasets[vectorName].push(dataset);
        }
        defaultSeverityRadarChart.data.datasets = datasets['default'];
        defaultSeverityRadarChart.update();
        cvss2P0SeverityRadarChart.data.datasets = datasets['CVSS:2.0'];
        cvss2P0SeverityRadarChart.update();
        cvss3P1SeverityRadarChart.data.datasets = datasets['CVSS:3.1'];
        cvss3P1SeverityRadarChart.update();
        cvss4P0SeverityRadarChart.data.datasets = datasets['CVSS:4.0'];
        cvss4P0SeverityRadarChart.update();

        const showCharts = {};
        showCharts['CVSS:2.0'] = useVersionedCharts && datasets['CVSS:2.0'].length > 0;
        showCharts['CVSS:3.1'] = useVersionedCharts && datasets['CVSS:3.1'].length > 0;
        showCharts['CVSS:4.0'] = useVersionedCharts && datasets['CVSS:4.0'].length > 0;
        showCharts['default'] = !showCharts['CVSS:2.0'] && !showCharts['CVSS:3.1'] && !showCharts['CVSS:4.0'];

        defaultSeverityRadarContainer.classList.add('d-none');
        cvss2P0SeverityRadarContainer.classList.add('d-none');
        cvss3P1SeverityRadarContainer.classList.add('d-none');
        cvss4P0SeverityRadarContainer.classList.add('d-none');

        if (cvssVectors.length > 0) {
            if (showCharts['default']) {
                defaultSeverityRadarContainer.classList.remove('d-none');
            }
            if (showCharts['CVSS:2.0']) {
                cvss2P0SeverityRadarContainer.classList.remove('d-none');
            }
            if (showCharts['CVSS:3.1']) {
                cvss3P1SeverityRadarContainer.classList.remove('d-none');
            }
            if (showCharts['CVSS:4.0']) {
                cvss4P0SeverityRadarContainer.classList.remove('d-none');
            }

            let firstShownChart = Array.from(additionalRadarChartContainer.getElementsByClassName('card')).find(card => !card.classList.contains('d-none'));
            // move toggle into card header
            try {
                severityRadarToggleContainer.remove();
            } catch (e) {
            }
            firstShownChart.getElementsByClassName('card-header')[0].appendChild(severityRadarToggleContainer);
        }

        // only show cvss4MacroVectorExplanationCard if a CVSS:4.0 vector is selected (selectedVector)
        // and show macro vector in cvss4MacroVectorExplanation
        if (cvssVectors.length > 0 && selectedVector && selectedVector.getVectorName() === 'CVSS:4.0') {
            cvss4MacroVectorExplanationCard.classList.remove('d-none');
            const macroVector = selectedVector.getMacroVector();

            function levelToText(level) {
                if (level === '0') {
                    return 'High';
                } else if (level === '1') {
                    return 'Medium';
                } else if (level === '2') {
                    return 'Low';
                } else {
                    return 'Unknown';
                }
            }

            const exploitability = levelToText(macroVector.getEq1().getLevel());
            const complexity = levelToText(macroVector.getEq2().getLevel());
            const vulnerableSystem = levelToText(macroVector.getEq3().getLevel());
            const subsequentSystem = levelToText(macroVector.getEq4().getLevel());
            const exploitation = levelToText(macroVector.getEq5().getLevel());
            const securityRequirements = levelToText(macroVector.getEq6().getLevel());
            const macroVectorString = macroVector.toString();
            cvss4MacroVectorExplanation.innerText = `Macro vector: ${macroVectorString}
Exploitability: ${exploitability}
Complexity: ${complexity}
Vulnerable system: ${vulnerableSystem}
Subsequent system: ${subsequentSystem}
Exploitation: ${exploitation}
Security requirements: ${securityRequirements}`;
        } else {
            cvss4MacroVectorExplanationCard.classList.add('d-none');
            cvss4MacroVectorExplanation.innerText = '';
        }


        // update the score details, append a table with headers for all scores that are present in any vector
        let hasOverall = false;
        let hasBase = false;
        let hasImpact = false;
        let hasExploitability = false;
        let hasTemporal = false;
        let hasEnvironmental = false;
        let hasModifiedImpact = false;
        for (let vector of cvssVectors) {
            const scores = vector.cvssInstance.calculateScores();
            if (!hasOverall && scores.overall !== undefined) hasOverall = true;
            if (!hasBase && scores.base !== undefined) hasBase = true;
            if (!hasImpact && scores.impact !== undefined) hasImpact = true;
            if (!hasExploitability && scores.exploitability !== undefined) hasExploitability = true;
            if (!hasTemporal && scores.temporal !== undefined) hasTemporal = true;
            if (!hasEnvironmental && scores.environmental !== undefined) hasEnvironmental = true;
            if (!hasModifiedImpact && scores.modifiedImpact !== undefined) hasModifiedImpact = true;
        }

        const table = document.createElement('table');
        table.classList.add('table', 'table-sm', 'table-striped', 'table-hover');
        const thead = document.createElement('thead');
        const tbody = document.createElement('tbody');
        table.appendChild(thead);
        table.appendChild(tbody);

        const headerRow = document.createElement('tr');
        thead.appendChild(headerRow);

        function appendHeaderCellIfPresent(headerName, present, elseValue = "") {
            if (present) {
                const cell = document.createElement('th');
                cell.innerText = headerName;
                headerRow.appendChild(cell);
            } else {
                const cell = document.createElement('th');
                cell.innerText = elseValue;
                headerRow.appendChild(cell);
            }
        }

        function appendContentCellIfPresent(row, headerName, present, elseValue = "") {
            if (present) {
                const cell = document.createElement('td');
                if (headerName instanceof HTMLElement) {
                    cell.appendChild(headerName);
                } else {
                    cell.innerText = headerName;
                }
                row.appendChild(cell);
            } else {
                const cell = document.createElement('td');
                cell.innerText = elseValue;
                row.appendChild(cell);
            }
        }

        appendHeaderCellIfPresent('Name', true);
        appendHeaderCellIfPresent('Overall', hasOverall);
        appendHeaderCellIfPresent('Base', hasBase);
        appendHeaderCellIfPresent('Impact', hasImpact);
        appendHeaderCellIfPresent('Exploitability', hasExploitability);
        appendHeaderCellIfPresent('Temporal', hasTemporal);
        appendHeaderCellIfPresent('Environmental', hasEnvironmental);
        appendHeaderCellIfPresent('Adj. Impact', hasModifiedImpact);

        for (let vector of cvssVectors) {
            const scores = vector.cvssInstance.calculateScores(false);
            const normalizedScores = vector.cvssInstance.calculateScores(true);
            const row = document.createElement('tr');
            tbody.appendChild(row);

            const nameElement = document.createElement('span');
            nameElement.innerText = vector.name;
            nameElement.classList.add('fw-bold');
            if (vector.cvssInstance instanceof CvssCalculator.Cvss2) {
                nameElement.classList.add('text-cvss-2');
            } else if (vector.cvssInstance instanceof CvssCalculator.Cvss3P1) {
                nameElement.classList.add('text-cvss-3P1');
            } else if (vector.cvssInstance instanceof CvssCalculator.Cvss4P0) {
                nameElement.classList.add('text-cvss-4P0');
            }

            appendContentCellIfPresent(row, nameElement, true);
            appendContentCellIfPresent(row, createScoreEntry(scores.overall, normalizedScores.overall), scores.overall !== undefined);
            appendContentCellIfPresent(row, createScoreEntry(scores.base, normalizedScores.base), scores.base !== undefined);
            appendContentCellIfPresent(row, createScoreEntry(scores.impact, normalizedScores.impact), scores.impact !== undefined);
            appendContentCellIfPresent(row, createScoreEntry(scores.exploitability, normalizedScores.exploitability), scores.exploitability !== undefined);
            appendContentCellIfPresent(row, createScoreEntry(scores.temporal, normalizedScores.temporal), scores.temporal !== undefined);
            appendContentCellIfPresent(row, createScoreEntry(scores.environmental, normalizedScores.environmental), scores.environmental !== undefined);
            appendContentCellIfPresent(row, createScoreEntry(scores.modifiedImpact, normalizedScores.modifiedImpact), scores.modifiedImpact !== undefined);
        }

        unregisterAllTooltips(cvssScoreDetailsContainerElement);
        cvssScoreDetailsContainerElement.innerText = '';
        // if there are no scores, don't show the table
        if (cvssVectors.length > 0) {
            cvssScoreDetailsContainerElement.appendChild(table);
        }

        function createScoreEntry(baseScore, normalizedScore) {
            const container = document.createElement('span');
            if (baseScore === normalizedScore) {
                container.innerHTML = coloredElementForSeverity(baseScore);
            } else {
                container.innerHTML = coloredElementForSeverity(baseScore) + ' → ' + coloredElementForSeverity(normalizedScore);
            }
            return container;
        }

        function coloredElementForSeverity(score) {
            const singleDigitScore = score === undefined ? undefined : score.toFixed(1);
            if (score === undefined) {
                return `<span style="color: var(--pastel-gray)">N/A</span>`;
            } else if (score <= 0.0) {
                return `<span style="color: var(--pastel-gray)">0.0</span>`;
            } else if (score < 4.0) {
                return `<span style="color: var(--strong-yellow)">${singleDigitScore}</span>`;
            } else if (score < 7.0) {
                return `<span style="color: var(--strong-light-orange)">${singleDigitScore}</span>`;
            } else if (score < 9.0) {
                return `<span style="color: var(--strong-dark-orange)">${singleDigitScore}</span>`;
            } else if (score <= 10.0) {
                return `<span style="color: var(--strong-red)">${singleDigitScore}</span>`;
            } else {
                return `<span style="color: var(--strong-purple)">${singleDigitScore}</span>`;
            }
        }

        // copy the vector container html content to the duplicated section
        if (selectedVectorContainerInstance) {
            selectedCvssDuplicatedSection.innerHTML = selectedVectorContainerInstance.domElement.outerHTML;
            selectedCvssDuplicatedSection.getElementsByClassName('cvss-vector-name')[0].value = selectedVectorContainerInstance.name;
            selectedCvssDuplicatedSection.getElementsByClassName('cvss-vector-string')[0].value = selectedVectorContainerInstance.cvssInstance.toString();
            selectedCvssDuplicatedSection.firstChild.classList.remove('cvss-active-selection');

            Array.from(selectedCvssDuplicatedSection.getElementsByTagName('input')).forEach(input => {
                input.setAttribute('readonly', 'readonly');
            });

            Array.from(selectedCvssDuplicatedSection.getElementsByClassName('cvss-vector-button-copy-to-clipboard')).forEach(button => {
                button.remove();
            });
            Array.from(selectedCvssDuplicatedSection.getElementsByClassName('cvss-vector-button-toggle-visibility')).forEach(button => {
                button.remove();
            });
            Array.from(selectedCvssDuplicatedSection.getElementsByClassName('cvss-vector-button-remove')).forEach(button => {
                button.remove();
            });

            for (let vectorElement of cvssVectors) {
                if (vectorElement === selectedVectorContainerInstance) {
                    selectedVectorContainerInstance.domElement.classList.add('upper-vector-selected');
                } else {
                    vectorElement.domElement.classList.remove('upper-vector-selected');
                }
            }

            updateTooltip(selectedCvssDuplicatedSection);
        } else {
            selectedCvssDuplicatedSection.innerHTML = '';
        }
    }, 10);
}

let selectedVector = null;
let expandedComponentCategories = [];

/**
 * Uses canvas.measureText to compute and return the width of the given text of given font in pixels.
 *
 * @param {String} text The text to be rendered.
 * @param {String} font The css font descriptor that text is to be rendered with (e.g. "bold 14px verdana").
 *
 * @see https://stackoverflow.com/questions/118241/calculate-text-width-with-javascript/21015393#21015393
 */
function getTextWidth(text, font) {
    // re-use canvas object for better performance
    const canvas = getTextWidth.canvas || (getTextWidth.canvas = document.createElement("canvas"));
    const context = canvas.getContext("2d");
    context.font = font;
    const metrics = context.measureText(text);
    return metrics.width;
}

function getCssStyle(element, prop) {
    return window.getComputedStyle(element, null).getPropertyValue(prop);
}

function getCanvasFont(el = document.body) {
    const fontWeight = getCssStyle(el, 'font-weight') || 'normal';
    const fontSize = getCssStyle(el, 'font-size') || '16px';
    const fontFamily = getCssStyle(el, 'font-family') || 'Times New Roman';

    return `${fontWeight} ${fontSize} ${fontFamily}`;
}

let abbreviatableComponentElements = [];

/*{
    element: element,
    textVariants: ['long', 'medium', 'short', ...]
}*/

function updateAbbreaviatableComponentElements() {
    for (let abbr of abbreviatableComponentElements) {
        const textVariants = abbr.textVariants;
        const element = abbr.element;

        const availableWidth = element.clientWidth;
        if (availableWidth === 0) {
            // console.warn('availableWidth is 0, skipping abbreviation');
            continue;
        }

        // now try to find the first that fits
        for (let textVariant of textVariants) {
            if (textVariant === undefined) {
                continue;
            }
            const usedWidth = getTextWidth(textVariant, getCanvasFont(element));
            if (usedWidth <= availableWidth) {
                element.innerText = textVariant;
                break;
            }
        }

        // if none fits, use the last one
        if (element.innerText === '') {
            element.innerText = textVariants[textVariants.length - 1];
        }
    }
}

// listen for page width changes, set a timeout for debouncing to 500ms
let abbreviationResizeTimeout = null;
window.addEventListener('resize', () => {
    clearTimeout(abbreviationResizeTimeout);
    abbreviationResizeTimeout = setTimeout(updateAbbreaviatableComponentElements, 500);
});

function setSelectedVector(vectorInstance) {
    selectedVector = vectorInstance;
    // now build the accordion
    unregisterAllTooltips(cvssComponentsContainerElement);
    cvssComponentsContainerElement.innerText = '';
    abbreviatableComponentElements = [];

    if (!vectorInstance) {
        return;
    }

    // mark the selected vector in the list by finding the index of the entry with the same vectorInstance
    for (let vector of cvssVectors) {
        if (vector.cvssInstance === vectorInstance) {
            vector.domElement.classList.add('cvss-active-selection');
        } else {
            vector.domElement.classList.remove('cvss-active-selection');
        }
    }

    const registeredComponents = vectorInstance.getRegisteredComponents(); // Map<ComponentCategory, VectorComponent<VectorComponentValue>[]>
    for (let componentCategory of registeredComponents.keys()) {
        const componentCategoryName = componentCategory.name;
        const componentsList = registeredComponents.get(componentCategory);

        const queryMap = new Map();
        queryMap.set(componentCategory, componentsList);
        let shouldBeCollapsed = !expandedComponentCategories.includes(componentCategoryName);

        const vectorComponentString = selectedVector.toString(true, queryMap).replace(selectedVector.getVectorPrefix(), '');
        const accordionItem = document.createElement('div');

        accordionItem.classList.add('accordion-item');
        if (selectedVector.constructor === CvssCalculator.Cvss4P0) {
            accordionItem.classList.add('accordion-cvss-4P0');
        } else if (selectedVector.constructor === CvssCalculator.Cvss3P1) {
            accordionItem.classList.add('accordion-cvss-3P1');
        } else if (selectedVector.constructor === CvssCalculator.Cvss2) {
            accordionItem.classList.add('accordion-cvss-2P0');
        }

        const accordionHeader = document.createElement('h2');

        accordionHeader.classList.add('accordion-header');
        const accordionButton = document.createElement('button');
        accordionButton.classList.add('accordion-button');
        if (shouldBeCollapsed) {
            accordionButton.classList.add('collapsed');
            accordionButton.setAttribute('aria-expanded', 'false');
        } else {
            accordionButton.setAttribute('aria-expanded', 'true');
        }
        accordionButton.type = 'button';
        accordionButton.setAttribute('data-bs-toggle', 'collapse');
        accordionButton.setAttribute('data-bs-target', `#cvss-component-details-${componentCategoryName}`);
        accordionButton.setAttribute('aria-controls', `cvss-component-details-${componentCategoryName}`);

        const accordionBadge = document.createElement('b');
        accordionBadge.classList.add('badge');
        let anyComponentSet = selectedVector.isCategoryPartiallyDefined(componentCategory);
        if (anyComponentSet) {
            accordionBadge.classList.add('bg-primary');
        } else {
            accordionBadge.classList.add('bg-secondary');
        }
        accordionBadge.innerText = capitalizeFirstLetter(componentCategoryName).replaceAll("-", " ");
        accordionButton.appendChild(accordionBadge);

        accordionButton.appendChild(document.createTextNode('\u00A0\u00A0'));

        const accordionVectorString = document.createElement('span');
        accordionVectorString.classList.add('font-monospace');
        accordionVectorString.style.wordWrap = 'anywhere';
        accordionVectorString.appendChild(document.createTextNode(vectorComponentString));
        accordionButton.appendChild(accordionVectorString);

        accordionHeader.appendChild(accordionButton);
        accordionItem.appendChild(accordionHeader);

        const accordionCollapse = document.createElement('div');
        accordionCollapse.id = `cvss-component-details-${componentCategoryName}`;
        accordionCollapse.classList.add('accordion-collapse');
        if (!shouldBeCollapsed) {
            accordionCollapse.classList.add('show');
        } else {
            accordionCollapse.classList.add('collapse');
        }
        // accordionCollapse.setAttribute('data-bs-parent', '#cvss-component-details'); // causes other accordions to collapse when this one is expanded

        const accordionBody = document.createElement('div');
        accordionBody.classList.add('accordion-body');
        {
            // create button groups for all components with a header that contains the component name
            let previousSubCategory = undefined;
            let isFirst = true;

            for (let component of componentsList) {
                if (previousSubCategory !== component.subCategory) {
                    previousSubCategory = component.subCategory;
                    const subCategoryHeader = document.createElement('div');
                    subCategoryHeader.classList.add('fw-bold', 'col-12', 'col-xl-12', 'col-xxl-12', 'mb-1');
                    if (!isFirst) {
                        subCategoryHeader.classList.add('mt-2');
                    }
                    subCategoryHeader.innerText = component.subCategory;
                    accordionBody.appendChild(subCategoryHeader);
                }

                const componentContainer = document.createElement('div');
                componentContainer.classList.add('columns', 'cvss-component-selection-element-container');
                accordionBody.appendChild(componentContainer);

                // header
                const componentHeader = document.createElement('div');
                componentHeader.innerText = component.name;
                componentHeader.setAttribute('data-bs-toggle', 'popover');
                componentHeader.setAttribute('data-bs-placement', 'left');
                componentHeader.setAttribute('title', component.shortName + ' - ' + component.name);
                if (component.description) {
                    componentHeader.setAttribute('data-bs-html', true);
                    componentHeader.setAttribute('data-bs-content', component.description + '<br/>Click component name to copy value to clipboard.');
                } else {
                    componentHeader.setAttribute('data-bs-content', 'Click component name to copy value to clipboard.');
                }
                componentHeader.setAttribute('data-bs-trigger', 'hover focus');
                componentHeader.classList.add('col-12', 'col-xl-3', 'col-xxl-3', 'align-middle', 'pe-2');
                componentHeader.addEventListener('click', () => {
                    copyText(component.shortName + ':' + currentValue.shortName);
                });
                componentHeader.style.cursor = 'pointer';
                componentContainer.appendChild(componentHeader);

                // buttons
                const componentButtonGroup = document.createElement('div');
                componentButtonGroup.classList.add('btn-group', 'mb-2', 'col-12', 'col-xl-9', 'col-xxl-9', 'columns', 'cvss-component-selection-button-container');
                componentButtonGroup.setAttribute('role', 'group');
                componentContainer.appendChild(componentButtonGroup);

                const currentValue = selectedVector.getComponent(component);
                for (let componentValue of component.values) {
                    if (componentValue.hide) {
                        continue;
                    }

                    const componentButton = document.createElement('button');
                    componentButtonGroup.appendChild(componentButton);
                    componentButton.classList.add('btn', 'btn-sm', 'cvss-component-button');
                    if (component.values.length > 5) {
                        componentButton.classList.add('col-2');
                    } else {
                        componentButton.classList.add('col-2-5');
                    }

                    componentButton.type = 'button';

                    // componentValue.description as popover tooltip
                    componentButton.setAttribute('data-bs-toggle', 'popover');
                    componentButton.setAttribute('data-bs-placement', 'top');
                    componentButton.setAttribute('data-bs-content', componentValue.description);
                    componentButton.setAttribute('title', componentValue.shortName + ' - ' + componentValue.name);
                    componentButton.setAttribute('data-bs-trigger', 'hover focus');

                    const buttonText = document.createElement('span');
                    buttonText.classList.add('button-text');
                    buttonText.innerText = componentValue.shortName + ': ' + componentValue.name;
                    abbreviatableComponentElements.push({
                        element: buttonText,
                        textVariants: [
                            componentValue.shortName + ': ' + componentValue.name,
                            componentValue.abbreviatedName ? componentValue.shortName + ': ' + componentValue.abbreviatedName : undefined,
                            componentValue.name,
                            componentValue.abbreviatedName,
                            componentValue.shortName
                        ]
                    });
                    componentButton.appendChild(buttonText);

                    if (componentValue === currentValue) {
                        let type = (componentValue.shortName === 'X' || componentValue.shortName === 'ND') ? 'outline-primary' : 'primary';
                        componentButton.classList.add('btn-' + type);
                    } else {
                        componentButton.classList.add('btn-outline-secondary');
                    }
                    componentButton.addEventListener('click', () => {
                        selectedVector.applyComponent(component, componentValue);
                    });
                }

                if (isFirst) {
                    isFirst = false;
                }
            }
        }
        accordionCollapse.appendChild(accordionBody);

        accordionItem.appendChild(accordionCollapse);

        cvssComponentsContainerElement.appendChild(accordionItem);

        // add listener to register whether the accordion is expanded or collapsed to add or remove it from the list of expanded categories
        accordionButton.addEventListener('click', () => {
            setTimeout(updateAbbreaviatableComponentElements, 30);
            if (shouldBeCollapsed) {
                expandedComponentCategories.push(componentCategoryName);
            } else {
                const index = expandedComponentCategories.indexOf(componentCategoryName);
                if (index > -1) {
                    expandedComponentCategories.splice(index, 1);
                }
            }
            shouldBeCollapsed = !shouldBeCollapsed;
            storeInGet();
        });

        updateTooltip(accordionCollapse);
    }

    updateAbbreaviatableComponentElements();

    storeInGet();
    updateScores();
}

function freeTextInputParseIntermediate() {
    const input = document.getElementById('inputAddVectorByMultipleStrings').value;
    const previewOlListElement = document.getElementById('appendVectorsFromStringModalPreview');
    previewOlListElement.innerText = '';

    const vectors = extractVectorsFromFreeText(input);
    for (let i = 0; i < vectors.length; i++) {
        const vector = vectors[i].vector;

        const cvssInstance = createInstanceForVector(vector);
        if (!cvssInstance) {
            const content = `
<div class="btn-group w-100 d-flex" role="group">
    <button type="button" class="btn bg-strong-red" style="width: 4rem;" data-bs-toggle="popover" data-bs-placement="right" data-bs-content="Low" data-bs-trigger="hover" readonly>?</button>
    <input type="text" class="btn button-no-break cvss-vector-name bg-pastel-gray" size="20" value="Invalid vector">
    <input type="text" class="btn btn-outline-secondary w-100 font-monospace text-start scrollable-content cvss-vector-string" value="${vector}" readonly>
</div>
`;
            const parentContentSpan = document.createElement('span');
            parentContentSpan.innerHTML = content;
            previewOlListElement.appendChild(parentContentSpan);
            continue;
        }

        let vectorName = cvssInstance.getVectorName();
        const screenWidth = window.innerWidth;
        if (screenWidth < 992) {
            vectorName = vectorName.replace('CVSS:', '');
        }
        let shortName = vectorName.replace('CVSS:', '');


        const prefix = vectors[i].prefix;
        const displayName = extractPossibleNameFromFreeText(prefix, vectorName, shortName);

        let overallScore = '?';
        let severityRange = {color: 'pastel-gray', severity: 'N/A'};
        try {
            overallScore = cvssInstance.calculateScores().overall.toFixed(1);
            severityRange = severityRangeColorFinder(overallScore);
        } catch (e) {
        }

        let vectorCssClass = 'bg-cvss-3P1';
        if (cvssInstance instanceof CvssCalculator.Cvss2) {
            vectorCssClass = 'bg-cvss-2';
        } else if (cvssInstance instanceof CvssCalculator.Cvss4P0) {
            vectorCssClass = 'bg-cvss-4P0';
        }

        const content = `
<div class="btn-group w-100 d-flex" role="group">
    <button type="button" class="btn bg-${severityRange.color}" style="width: 4rem;" data-bs-toggle="popover" data-bs-placement="right" data-bs-content="Low" data-bs-trigger="hover" readonly>${overallScore}</button>
    <input type="text" class="btn button-no-break cvss-vector-name ${vectorCssClass}" size="20" value="${displayName}">
    <input type="text" class="btn btn-outline-secondary w-100 font-monospace text-start scrollable-content cvss-vector-string" value="${vector}" readonly>
</div>
`;
        const parentContentSpan = document.createElement('span');
        parentContentSpan.innerHTML = content;
        previewOlListElement.appendChild(parentContentSpan);
    }

    const setVisibilityIfNotEmpty = document.getElementsByClassName('only-if-append-vectors-available');
    if (previewOlListElement.innerText !== '') {
        for (let i = 0; i < setVisibilityIfNotEmpty.length; i++) {
            setVisibilityIfNotEmpty[i].classList.remove('d-none');
        }
    } else {
        for (let i = 0; i < setVisibilityIfNotEmpty.length; i++) {
            setVisibilityIfNotEmpty[i].classList.add('d-none');
        }

    }
}

function appendNewVectorsFromFreeTextInput() {
    const previewParent = document.getElementById('appendVectorsFromStringModalPreview');
    const previewChildren = previewParent.children;
    for (let i = 0; i < previewChildren.length; i++) {
        const child = previewChildren[i];
        const name = child.getElementsByClassName('cvss-vector-name')[0].value;
        const vector = child.getElementsByClassName('cvss-vector-string')[0].value;
        appendNewVector(vector, name);
    }

    document.getElementById('inputAddVectorByMultipleStrings').value = '';
    freeTextInputParseIntermediate();
}

function copyVectors() {
    const vectors = [];
    for (let vector of cvssVectors) {
        vectors.push([vector.cvssInstance.calculateScores().overall, vector.name, vector.cvssInstance.toString()]);
    }
    const longestNameLength = vectors.reduce((acc, cur) => Math.max(acc, cur[1].length), 0);

    let formattedText = '';
    for (let vector of vectors) {
        formattedText += `${('' + vector[0].toFixed(1)).padEnd(4, ' ')} ${vector[1].padEnd(longestNameLength, ' ')} ${vector[2]}`;
        formattedText += '\n';
    }

    try {
        navigator.clipboard.writeText(formattedText);
        createBootstrapToast('Copied vectors', 'Copied all vectors to clipboard.', 'success');
    } catch (e) {
        console.error(e);
        alert('Copy the following text by highlighting it and using ctrl/cmd + c:\n' + formattedText);
    }
}

function copyLink() {
    try {
        navigator.clipboard.writeText(window.location.href);
        createBootstrapToast('Copied link', 'Copied link to clipboard.', 'success');
    } catch (e) {
        console.error(e);
        alert('Copy the following text by highlighting it and using ctrl/cmd + c:\n' + window.location.href);
    }
}

function copyText(text, displayName = undefined) {
    try {
        navigator.clipboard.writeText(text);
        createBootstrapToast('Copied to clipboard', 'Copied ' + (displayName ? displayName : (text.length < 20 ? '"' + text + '"' : 'text')) + ' to clipboard.', 'success');
    } catch (e) {
        console.error(e);
        if (text.includes('\n')) {
            alert('Copy the following text by highlighting it and using ctrl/cmd + c:\n' + text);
        } else {
            prompt('Copy the following text by highlighting it and using ctrl/cmd + c:', text);
        }
    }
}

function updateTooltip(element) {
    const tooltipTriggerList = [].slice.call(element.querySelectorAll('[data-bs-toggle="popover"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Popover(tooltipTriggerEl);
    });
}

function unregisterAllTooltips(element) {
    // find all that have already been initialized and destroy them
    const tooltipTriggerList = [].slice.call(element.querySelectorAll('[data-bs-toggle="popover"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        const popover = bootstrap.Popover.getInstance(tooltipTriggerEl);
        if (popover) {
            popover.dispose();
        }
    });
}

function createBootstrapToast(title, message, type = 'info') {
    let toastContainer = document.getElementById('toast-container');
    if (!toastContainer) {
        toastContainer = document.createElement('div');
        toastContainer.id = 'toast-container';
        toastContainer.className = 'toast-container position-fixed top-0 end-0 p-3';
        document.body.appendChild(toastContainer);
    }

    const toastId = `toast-${Date.now()}`;

    const iconColors = {
        info: '#007aff',
        warning: '#ffc107',
        success: '#28a745',
        error: '#dc3545'
    };
    const iconColor = iconColors[type] || iconColors.info;

    const toast = document.createElement('div');
    toast.className = 'toast';
    toast.id = toastId;
    toast.role = 'alert';
    toast.ariaLive = 'assertive';
    toast.ariaAtomic = 'true';
    toast.innerHTML = `
    <div class="toast-header">
      <svg class="bd-placeholder-img rounded me-2" width="20" height="20" xmlns="http://www.w3.org/2000/svg" aria-hidden="true" preserveAspectRatio="xMidYMid slice" focusable="false">
        <rect width="100%" height="100%" fill="${iconColor}"></rect>
      </svg>
      <strong class="me-auto">${title}</strong>
      <button type="button" class="btn-close btn-close-white" data-bs-dismiss="toast" aria-label="Close"></button>
    </div>
    <div class="toast-body">
      ${message}
    </div>
  `;

    toastContainer.appendChild(toast);

    const bootstrapToast = new bootstrap.Toast(toast, {
        autohide: true,
        delay: 4000
    });
    bootstrapToast.show();
}

function loadFromGet() {
    const urlParams = new URLSearchParams(window.location.search);

    const gzipParam = urlParams.get('b64gzip');
    if (gzipParam) {
        const decompressedParams = decompressBase64GzipParam(gzipParam);
        const additionalParams = new URLSearchParams(decompressedParams);

        // append additional parameters to urlParams
        for (const [key, value] of additionalParams) {
            urlParams.append(key, value);
        }
    }

    const vector = urlParams.get('vector');
    if (vector) {
        const parsedVectorData = JSON.parse(vector);
        for (let [name, shown, vector, version] of parsedVectorData) {
            if (vector.length === 0) {
                continue;
            }
            if (!name || name.length === 0) {
                name = undefined;
            }
            appendNewVector(vector, name, shown, version);
        }
    }

    const open = urlParams.get('open');
    if (open) {
        expandedComponentCategories = open.split(',');
    }

    const selectedVectorName = urlParams.get('selected');
    if (selectedVectorName) {
        for (let vector of cvssVectors) {
            if (vector.name === selectedVectorName) {
                setSelectedVector(vector.cvssInstance);
                break;
            }
        }
    }

    const cve = urlParams.get('cve');
    if (cve) {
        const cves = cve.split(',');
        let currentIndex = 0;
        const loadNext = () => {
            if (currentIndex < cves.length) {
                appendVectorByVulnerability(cves[currentIndex], () => {
                    currentIndex++;
                    loadNext();
                });
            }
        }
        loadNext();
    }
}

function decompressBase64GzipParam(encodedString) {
    const binaryString = atob(encodedString.replace(/-/g, '+').replace(/_/g, '/'));
    const charData = binaryString.split('').map(c => c.charCodeAt(0));
    const binData = new Uint8Array(charData);
    return pako.inflate(binData, {to: 'string'});
}

let storeInGetTimeout = null;

function storeInGet() {
    if (storeInGetTimeout) {
        clearTimeout(storeInGetTimeout);
    }

    storeInGetTimeout = setTimeout(() => {
        let vectorData = [];
        for (let vector of cvssVectors) {
            vectorData.push([vector.name, vector.shown, vector.cvssInstance.toString(), vector.cvssInstance.getVectorName()]);
        }
        const openAccordions = expandedComponentCategories.join(',');

        let urlParams = new URLSearchParams(window.location.search);

        if (vectorData.length === 0) {
            urlParams.delete('vector');
            urlParams.delete('open');
        } else {
            urlParams.set('vector', JSON.stringify(vectorData));
            if (openAccordions.length > 0) {
                urlParams.set('open', openAccordions);
            }
        }

        if (selectedVector) {
            let found = false;
            for (let vector of cvssVectors) {
                if (vector.cvssInstance === selectedVector) {
                    urlParams.set('selected', vector.name);
                    found = true;
                    break;
                }
            }
            if (!found) {
                urlParams.delete('selected');
            }
        } else {
            urlParams.delete('selected');
        }

        urlParams.delete('cve');
        urlParams.delete('b64gzip');

        if (urlParams.toString().length === 0) {
            window.history.replaceState({}, '', window.location.pathname);
        } else {
            window.history.replaceState({}, '', '?' + urlParams.toString());
        }
    }, 200);
}

updateTooltip(document.body);
loadFromGet();
try {
    freeTextInputParseIntermediate();
} catch (e) {
}

if (cvssVectors.length === 0) {
    // const defaultVector = new CvssCalculator.Cvss3P1();
    // defaultVector.fillAverageVector();
    // appendNewVector(defaultVector.toString(), '3.1');
    // setSelectedVector(cvssVectors[0].cvssInstance);
    // appendVectorByVulnerability('CVE-2020-3453');
    expandedComponentCategories.push('base');
    updateScores();
}

function loadDemo() {
    const demoString = 'vector=%5B%5B%22CVSS%3A4.0%22%2Ctrue%2C%22CVSS%3A4.0%2FAV%3AP%2FAC%3AL%2FAT%3AN%2FPR%3AN%2FUI%3AN%2FVC%3AH%2FVI%3AL%2FVA%3AL%2FSC%3AH%2FSI%3AH%2FSA%3AH%22%2C%22CVSS%3A4.0%22%5D%2C%5B%223.1+2020-5934+%28nist.gov%29%22%2Ctrue%2C%22CVSS%3A3.1%2FAV%3AN%2FAC%3AL%2FPR%3AL%2FUI%3AN%2FS%3AC%2FC%3AH%2FI%3AL%2FA%3AH%2FE%3AF%2FRL%3AU%2FRC%3AR%22%2C%22CVSS%3A3.1%22%5D%2C%5B%222.0+2020-5934+%28nist.gov%29%22%2Ctrue%2C%22AV%3AL%2FAC%3AH%2FAu%3AS%2FC%3AC%2FI%3AP%2FA%3AN%2FE%3AU%2FRL%3AU%2FRC%3AC%2FCDP%3ALM%2FTD%3AM%2FCR%3AH%2FIR%3AH%2FAR%3AH%22%2C%22CVSS%3A2.0%22%5D%5D&open=temporal&selected=3.1+2020-5934+%28nist.gov%29';
    const baseUrl = window.location.href.split('?')[0];
    const decodedDemoString = decodeURIComponent(demoString);
    window.location.href = baseUrl + '?' + decodedDemoString;
}
