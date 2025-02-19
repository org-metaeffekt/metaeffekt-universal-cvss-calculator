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

    constructor(name, cvssInstance, shown, initialCvssInstance) {
        this.initialCvssInstance = initialCvssInstance;
        this.officialCvssInstance = undefined;
        this.cvssInstance = cvssInstance;
        this.name = name;
        this.shown = shown === undefined ? true : shown;
        this.hasBeenDestroyed = false;
        this.uniqueId = Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);

        const [domElement, scoreDisplayButton, nameElement, vectorStringElement, copyVectorToClipboardButton, visibilityToggleButton, cloneButton, removeButton] = this.createDomElement();
        this.domElement = domElement;
        this.scoreDisplayButton = scoreDisplayButton;
        this.nameElement = nameElement;
        this.vectorStringElement = vectorStringElement;
        this.copyVectorToClipboardButton = copyVectorToClipboardButton;
        this.visibilityToggleButton = visibilityToggleButton;
        this.cloneButton = cloneButton;
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

        // drag and drop support for moving the element up and down in its container and the cvss vector list
        const draggableElements = [this.scoreDisplayButton, this.copyVectorToClipboardButton, this.visibilityToggleButton, this.cloneButton, this.removeButton];

        for (let draggableElement of draggableElements) {
            draggableElement.setAttribute('draggable', 'true');
            draggableElement.addEventListener('dragstart', event => {
                event.dataTransfer.setData('text/plain', this.uniqueId);
                event.dataTransfer.effectAllowed = 'move';
                this.domElement.classList.add('dragging');
                unregisterAllTooltips(draggableElement);
            });
            draggableElement.addEventListener('dragend', event => {
                this.domElement.classList.remove('dragging');
                updateTooltip(draggableElement);
            });
        }

        this.domElement.addEventListener('dragover', event => {
            event.preventDefault();
            event.dataTransfer.dropEffect = 'move';
            this.domElement.classList.add('dragover');
        });
        this.domElement.addEventListener('dragleave', event => {
            this.domElement.classList.remove('dragover');
        });
        this.domElement.addEventListener('drop', event => {
            event.preventDefault();
            const draggedElementId = event.dataTransfer.getData('text/plain');
            const draggedElement = cvssVectors.find(vector => vector.uniqueId === draggedElementId);
            if (draggedElement) {
                const draggedElementIndex = cvssVectors.indexOf(draggedElement);
                const thisElementIndex = cvssVectors.indexOf(this);
                if (draggedElementIndex > -1 && thisElementIndex > -1) {
                    cvssVectors.splice(draggedElementIndex, 1);
                    cvssVectors.splice(thisElementIndex, 0, draggedElement);
                    this.rearrangeOrderBasedOnCvssList(cvssVectorListContainerElement);
                    updateScores();
                    storeInGet();

                    // remove dragover class from all elements
                    const dragoverElements = document.getElementsByClassName('dragover');
                    for (let i = 0; i < dragoverElements.length; i++) {
                        dragoverElements[i].classList.remove('dragover');
                    }
                }
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

        this.nameElement.addEventListener('contextmenu', e => {
            if (!this.officialCvssInstance) {
                return;
            }
            e.preventDefault();
            this.cvssInstance.clearComponents();
            this.cvssInstance.applyVector(this.officialCvssInstance.toString());
            updateScores();
            storeInGet();
        });

        this.cloneButton.addEventListener('click', () => {
            if (this.hasBeenDestroyed) {
                return;
            }

            if (event.altKey || event.metaKey || event.ctrlKey || event.shiftKey) {
                downloadText('cvss-vector-' + this.name + '.json', JSON.stringify(this.createJsonSchema()));
            } else {
                this.cloneAndAppendVector();
                updateScores();

                setTimeout(() => {
                    const lastVector = cvssVectors[cvssVectors.length - 1];
                    setSelectedVector(lastVector.cvssInstance);
                }, 1);
            }
        });

        // remove button
        this.removeButton.addEventListener('click', event => {
            if (this.hasBeenDestroyed) {
                return;
            }

            if (event.altKey || event.metaKey || event.ctrlKey || event.shiftKey) {
                this.cvssInstance.clearComponents();
                updateScores();
                storeInGet();
                setTimeout(() => {
                    this.vectorStringElement.value = this.cvssInstance.toString();
                }, 10);

            } else {
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
            }
        });

        this.visibilityToggleButton.addEventListener('click', e => {
            if (this.hasBeenDestroyed) {
                return;
            }
            // check if shift or command (meta) is pressed
            if (e.altKey || e.metaKey || e.ctrlKey || e.shiftKey) {
                this.cvssInstance.applyEnvironmentalMetricsOntoBase();
            } else {
                this.shown = !this.shown;
            }
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

    rearrangeOrderBasedOnCvssList(container) {
        while (container.firstChild) {
            container.removeChild(container.firstChild);
        }
        for (let vector of cvssVectors) {
            container.appendChild(vector.domElement);
        }
    }

    cloneAndAppendVector() {
        const cvssInstance = this.cvssInstance.clone();
        const name = this.name;
        const vectorRepresentation = new CvssVectorRepresentation(name, cvssInstance, true, cvssInstance.clone());
        vectorRepresentation.appendTo(cvssVectorListContainerElement);
        cvssVectors.push(vectorRepresentation);
        vectorRepresentation.adjustNameColumnSize();
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
            } else if (this.cvssInstance instanceof CvssCalculator.Cvss3P0) {
                nameElement.classList.add('bg-cvss-3P0');
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
            copyVectorToClipboardButton.setAttribute('data-bs-content', 'Copy vector to clipboard or shift-click to copy only components that changed since adding them to this page.');
            copyVectorToClipboardButton.setAttribute('data-bs-trigger', 'hover');
            copyVectorToClipboardButton.setAttribute('data-cvss-shift-action', 'true');
            copyVectorToClipboardButton.setAttribute('data-cvss-shift-action-replacement-icon', 'clipboard-pulse');
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
            visibilityToggleButton.setAttribute('data-bs-content', 'Toggle visibility or shift-click to apply the environmental metrics back onto the base metrics.');
            visibilityToggleButton.setAttribute('data-bs-trigger', 'hover');
            visibilityToggleButton.setAttribute('data-cvss-shift-action', 'true');
            visibilityToggleButton.setAttribute('data-cvss-shift-action-replacement-icon', 'layer-forward');
            const visibilityIcon = document.createElement('i');
            visibilityIcon.classList.add('bi', 'bi-eye');
            visibilityToggleButton.appendChild(visibilityIcon);
            domElement.appendChild(visibilityToggleButton);
        }

        const cloneButton = document.createElement('button');
        {
            cloneButton.type = 'button';
            cloneButton.classList.add('btn', 'btn-outline-primary', 'cvss-vector-button-copy-to-clipboard');
            cloneButton.setAttribute('data-bs-toggle', 'popover');
            cloneButton.setAttribute('data-bs-placement', 'bottom');
            cloneButton.setAttribute('data-bs-content', 'Clone this vector or shift-click to download this vector\'s data as JSON.');
            cloneButton.setAttribute('data-bs-trigger', 'hover');
            cloneButton.setAttribute('data-cvss-shift-action', 'true');
            cloneButton.setAttribute('data-cvss-shift-action-replacement-icon', 'braces');
            const copyIcon = document.createElement('i');
            copyIcon.classList.add('bi', 'bi-copy');
            cloneButton.appendChild(copyIcon);
            domElement.appendChild(cloneButton);
        }

        const removeButton = document.createElement('button');
        {
            removeButton.type = 'button';
            removeButton.classList.add('btn', 'btn-outline-danger', 'cvss-vector-button-remove');
            removeButton.setAttribute('data-bs-toggle', 'popover');
            removeButton.setAttribute('data-bs-placement', 'right');
            removeButton.setAttribute('data-bs-content', 'Remove vector or shift-click to clear all vector components.');
            removeButton.setAttribute('data-bs-trigger', 'hover');
            removeButton.setAttribute('data-cvss-shift-action', 'true');
            removeButton.setAttribute('data-cvss-shift-action-replacement-icon', 'eraser');
            const removeIcon = document.createElement('i');
            removeIcon.classList.add('bi', 'bi-dash-circle');
            removeButton.appendChild(removeIcon);
            domElement.appendChild(removeButton);
        }

        updateTooltip(domElement);

        return [domElement, scoreDisplayButton, nameElement, vectorStringElement, copyVectorToClipboardButton, visibilityToggleButton, cloneButton, removeButton];
    }

    static findRealRenderedTextWidthWithFontOfElement(referenceElement, text) {
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

        const actualWidth = CvssVectorRepresentation.findRealRenderedTextWidthWithFontOfElement(this.nameElement, maxLengthName);
        // this calculation should be unnecessary now considering the change with adding the maxWidth attribute below, but I will still include it for now.
        const targetSize = actualWidth / (actualWidth < 100 ? 6 : (actualWidth < 165 ? 5.2 : (actualWidth < 270 ? 5 : (actualWidth < 320 ? 4.4 : (actualWidth < 380 ? 4 : (3))))));
        for (let vector of cvssVectors) {
            vector.nameElement.size = targetSize;
            vector.nameElement.style.maxWidth = actualWidth + 30 + 'px';
        }
    }

    getCveName() {
        return extractAndFormatCVE(this.name);
    }

    createJsonSchema() {
        return this.cvssInstance.createJsonSchema();
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
    '3.0': CvssCalculator.Cvss3P0,
    '4.0': CvssCalculator.Cvss4P0,
    'CVSS:2.0': CvssCalculator.Cvss2,
    'CVSS:3.1': CvssCalculator.Cvss3P1,
    'CVSS:3.0': CvssCalculator.Cvss3P0,
    'CVSS:4.0': CvssCalculator.Cvss4P0
}

const mainCvssCalculatorContainerElement = document.getElementById('mainCvssCalculatorContainer');
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
appendRadarChartToContainer(additionalRadarChartContainer, 'CVSS:3.0');
appendRadarChartToContainer(additionalRadarChartContainer, 'CVSS:2.0');
const defaultSeverityRadarChart = constructRadarChartInstance('defaultSeverityRadar');
const cvss4P0SeverityRadarChart = constructRadarChartInstance('CVSS:4.0SeverityRadar');
const cvss3P1SeverityRadarChart = constructRadarChartInstance('CVSS:3.1SeverityRadar');
const cvss3P0SeverityRadarChart = constructRadarChartInstance('CVSS:3.0SeverityRadar');
const cvss2P0SeverityRadarChart = constructRadarChartInstance('CVSS:2.0SeverityRadar');

const defaultSeverityRadarContainer = document.getElementById('defaultSeverityRadarContainer');
const cvss4P0SeverityRadarContainer = document.getElementById('CVSS:4.0SeverityRadarContainer');
const cvss3P1SeverityRadarContainer = document.getElementById('CVSS:3.1SeverityRadarContainer');
const cvss3P0SeverityRadarContainer = document.getElementById('CVSS:3.0SeverityRadarContainer');
const cvss2P0SeverityRadarContainer = document.getElementById('CVSS:2.0SeverityRadarContainer');

const cvssVectors = [];
let chartInterpolationMethod = 'base'; // interpolated | base

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
        // - first attempt: try to find a CVSS-prefix using the name of the vector
        for (let versionName in cvssVersionConstructors) {
            const specificVectorClass = cvssVersionConstructors[versionName];
            if (vectorInput.startsWith(versionName)) {
                try {
                    return new specificVectorClass(vectorInput);
                } catch (e) {
                }
            }
        }
        // - second attempt: just let each class parse the vector string and return the first one that doesn't throw an error
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

function appendNewVector(vectorInput, name, shown = true, version = undefined, unmodifiedVector = undefined) {
    const cvssInstance = createInstanceForVector(vectorInput, version);
    const initialVectorInstance = unmodifiedVector ? createInstanceForVector(unmodifiedVector, cvssInstance.getVectorName()) : cvssInstance.clone();
    if (cvssInstance) {
        if (!name) {
            name = cvssInstance.getVectorName()
            const screenWidth = window.innerWidth;
            if (screenWidth < 992) {
                name = name.replace('CVSS:', '');
            }
        }
        const vectorRepresentation = new CvssVectorRepresentation(name, cvssInstance, shown, initialVectorInstance);
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

function appendNewEmptyVector(vectorInput, name, prependCvssOnLargeScreens = false, fillRandomBaseVector = true) {
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
        if (fillRandomBaseVector) {
            cvssInstance.fillRandomBaseVector();
        }
        const vectorRepresentation = new CvssVectorRepresentation(name, cvssInstance, true, cvssInstance.clone());
        vectorRepresentation.appendTo(cvssVectorListContainerElement);
        cvssVectors.push(vectorRepresentation);
        vectorRepresentation.adjustNameColumnSize();
        updateScores();
        setSelectedVector(cvssInstance);
    } else {
        invalidVectorToast(vectorInput, name);
    }
}

function appendNewEmptyVectorButtonClick(event, vectorInput, name, prependCvssOnLargeScreens = false) {
    appendNewEmptyVector(vectorInput, name, prependCvssOnLargeScreens, event && (event.altKey || event.metaKey || event.ctrlKey || event.shiftKey));
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

function cloneAllVectors() {
    const vectorCount = cvssVectors.length;
    for (let i = 0; i < vectorCount; i++) {
        const vector = cvssVectors[i];
        vector.cloneAndAppendVector();
    }
    updateScores();
    storeInGet();
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
    inputElement.setAttribute('disabled', 'disabled');

    isCurrentlyFetchingFromVulnerability = true;

    fetchVulnerabilityData(vulnerability)
        .then(json => {
            inputElement.removeAttribute('disabled');
            isCurrentlyFetchingFromVulnerability = false;
            const cvssVectors = getCvssVectorsAssumeFetched(vulnerability);
            const englishDescription = getEnglishDescriptionAssumeFetched(vulnerability);

            if (cvssVectors.length === 0) {
                createBootstrapToast('Error fetching from NVD', 'No CVSS vector found for ' + vulnerability, 'error');
                return;
            }

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

function interpolateChartScoresBaseScores(scores) {
    if (isNotDefined(scores.environmental) && scores.base) {
        scores.environmental = scores.base;
    }
    if (isNotDefined(scores.modifiedImpact) && scores.impact) {
        scores.modifiedImpact = scores.impact;
    }
    if (isNotDefined(scores.temporal) && scores.base) {
        scores.temporal = scores.base;
    }
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

        // try to find official vectors
        for (let vector of cvssVectors) {
            const cvssVectorInstance = vector.cvssInstance;
            const officialVector = vector.cvssInstance.officialCvssInstance;
            const cvssVectorCveName = vector.getCveName();
            if (!officialVector && cvssVectorInstance && cvssVectorCveName) {
                getCvssVectors(cvssVectorCveName)
                    .then(vectors => {
                        vectors = vectors.map(v => {
                            const instance = createInstanceForVector(v.vector);
                            if (instance && instance.constructor === cvssVectorInstance.constructor) {
                                return instance;
                            }
                            return null;
                        }).filter(v => v !== null);
                        if (vectors.length === 0) {
                            console.error('No official vector found for', cvssVectorCveName);
                            return;
                        } else if (vectors.length === 1) {
                            vector.officialCvssInstance = vectors[0];
                        } else {
                            let smallestDiffVectorSize = Infinity;
                            let smallestDiffVector = null;
                            for (let vector of vectors) {
                                const diffVector = vector.diffVector(cvssVectorInstance);
                                if (diffVector.size() < smallestDiffVectorSize) {
                                    smallestDiffVectorSize = diffVector.size();
                                    smallestDiffVector = vector;
                                }
                            }
                            vector.officialCvssInstance = smallestDiffVector;
                        }

                        if (vector.officialCvssInstance) {
                            const nameElement = vector.nameElement;
                            const diff = vector.officialCvssInstance.diffVector(cvssVectorInstance).size();
                            if (diff > 0) {
                                nameElement.classList.add('fst-italic');
                                nameElement.setAttribute('data-bs-toggle', 'popover');
                                nameElement.setAttribute('data-bs-placement', 'bottom');
                                nameElement.setAttribute('data-bs-title', 'Vector modified');
                                nameElement.setAttribute('data-bs-content', 'The vector displayed here has been modified from the official vector for ' + cvssVectorCveName + ' by ' + diff + ' metrics. Right-click this element to reset to the official vector: ' + vector.officialCvssInstance.toString());
                                nameElement.setAttribute('data-bs-trigger', 'hover');
                                updateTooltip(nameElement.parentElement);
                            } else {
                                nameElement.classList.remove('fst-italic');
                                unregisterAllTooltips(nameElement);
                            }
                        }
                    });
            }
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

            getEnglishDescription(vulnerabilityName)
                .then(description => {
                    if (description) {
                        cveDetailsDisplayTitle.innerText = vulnerabilityName;
                        cveDetailsDisplay.innerText = description;
                        cveDetailsDisplayTitle.href = 'https://nvd.nist.gov/vuln/detail/' + vulnerabilityName;
                        cveDetailsDisplayCard.classList.remove('d-none');
                    } else {
                        cveDetailsDisplayCard.classList.add('d-none');
                    }
                }).catch(error => {
                cveDetailsDisplayCard.classList.add('d-none');
            });
        } else {
            cveDetailsDisplayCard.classList.add('d-none');
        }

        // now update the charts and the score table
        const datasets = {'default': [], 'CVSS:2.0': [], 'CVSS:3.0': [], 'CVSS:3.1': [], 'CVSS:4.0': []};
        const useVersionedCharts = !document.getElementById('severityRadarToggle').checked;

        const calculatedVectorScores = {};
        const calculatedNormalizedVectorScores = {};
        for (let vector of cvssVectors) {
            calculatedVectorScores[vector.uniqueId] = vector.cvssInstance.calculateScores(false);
            calculatedNormalizedVectorScores[vector.uniqueId] = vector.cvssInstance.calculateScores(true);
        }

        for (let vector of cvssVectors) {
            const scores = calculatedVectorScores[vector.uniqueId];
            const normalizedScores = calculatedNormalizedVectorScores[vector.uniqueId];
            const vectorName = vector.cvssInstance.getVectorName();

            if (vector.cvssInstance instanceof CvssCalculator.Cvss4P0) {
                normalizedScores.base = normalizedScores.overall;
                normalizedScores.impact = normalizedScores.overall;
                normalizedScores.exploitability = normalizedScores.overall;
                normalizedScores.modifiedImpact = normalizedScores.overall;
                normalizedScores.temporal = normalizedScores.overall;
                normalizedScores.environmental = normalizedScores.overall;
            }

            if (!isNotDefined(normalizedScores.overall)) {
                const severityRange = severityRangeColorFinder(normalizedScores.overall);
                vector.scoreDisplayButton.classList.remove('bg-pastel-gray', 'bg-strong-yellow', 'bg-strong-light-orange', 'bg-strong-dark-orange', 'bg-strong-red');
                vector.scoreDisplayButton.classList.add('bg-' + severityRange.color);
                vector.scoreDisplayButton.setAttribute('data-bs-toggle', 'popover');
                vector.scoreDisplayButton.setAttribute('data-bs-placement', 'left');
                vector.scoreDisplayButton.setAttribute('data-bs-html', 'true');
                vector.scoreDisplayButton.setAttribute('data-bs-content', '<b>' + severityRange.severity + '</b><br><small>Drag to reorder</small>');
                vector.scoreDisplayButton.setAttribute('data-bs-trigger', 'hover');

                if (normalizedScores.overall === 0 && !vector.cvssInstance.isBaseFullyDefined()) {
                    vector.scoreDisplayButton.innerHTML = '<i class="bi bi-exclamation-triangle-fill"></i>';
                    vector.scoreDisplayButton.setAttribute('data-bs-content', 'All base metrics must be defined to calculate CVSS scores.');
                } else if (normalizedScores.overall !== 10) {
                    vector.scoreDisplayButton.innerText = normalizedScores.overall.toFixed(1);
                } else {
                    vector.scoreDisplayButton.innerText = '10';
                }

                unregisterAllTooltips(vector.scoreDisplayButton.parentElement);
                updateTooltip(vector.scoreDisplayButton.parentElement);
            }

            // chart
            const isPointDefined = [normalizedScores.base, normalizedScores.modifiedImpact, normalizedScores.impact, normalizedScores.temporal, normalizedScores.exploitability, normalizedScores.environmental].map(v => isNaN(v) ? 0 : (selectedVector === vector.cvssInstance ? 3 : 4));

            if (chartInterpolationMethod === 'interpolated') {
                interpolateChartScores(normalizedScores);
            } else {
                interpolateChartScoresBaseScores(normalizedScores);
            }

            let color = [180, 48, 52];
            if (vectorName === 'CVSS:2.0') {
                color = [347, 100, 69];
            } else if (vectorName === 'CVSS:3.0') {
                color = [204, 82, 40];
            } else if (vectorName === 'CVSS:3.1') {
                color = [204, 82, 57];
            } else if (vectorName === 'CVSS:4.0') {
                color = [57, 72, 54];
            }

            // modify the color a bit randomly seeded based on the vector.getName() to make it more distinguishable
            let seed = vector.uniqueId.split('').reduce((acc, cur) => acc + cur.charCodeAt(0), 0);
            seed = ((seed % 60) - 30);
            color[0] = (color[0] + seed + 360) % 360;

            const dataset = {
                label: vector.name,
                data: [normalizedScores.base, normalizedScores.modifiedImpact, normalizedScores.impact, normalizedScores.temporal, normalizedScores.exploitability, normalizedScores.environmental],
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
        cvss3P0SeverityRadarChart.data.datasets = datasets['CVSS:3.0'];
        cvss3P0SeverityRadarChart.update();
        cvss3P1SeverityRadarChart.data.datasets = datasets['CVSS:3.1'];
        cvss3P1SeverityRadarChart.update();
        cvss4P0SeverityRadarChart.data.datasets = datasets['CVSS:4.0'];
        cvss4P0SeverityRadarChart.update();

        const showCharts = {};
        showCharts['CVSS:2.0'] = useVersionedCharts && datasets['CVSS:2.0'].length > 0;
        showCharts['CVSS:3.0'] = useVersionedCharts && datasets['CVSS:3.0'].length > 0;
        showCharts['CVSS:3.1'] = useVersionedCharts && datasets['CVSS:3.1'].length > 0;
        showCharts['CVSS:4.0'] = useVersionedCharts && datasets['CVSS:4.0'].length > 0;
        showCharts['default'] = !showCharts['CVSS:2.0'] && !showCharts['CVSS:3.0'] && !showCharts['CVSS:3.1'] && !showCharts['CVSS:4.0'];

        defaultSeverityRadarContainer.classList.add('d-none');
        cvss2P0SeverityRadarContainer.classList.add('d-none');
        cvss3P0SeverityRadarContainer.classList.add('d-none');
        cvss3P1SeverityRadarContainer.classList.add('d-none');
        cvss4P0SeverityRadarContainer.classList.add('d-none');

        if (cvssVectors.length > 0) {
            if (showCharts['default']) {
                defaultSeverityRadarContainer.classList.remove('d-none');
            }
            if (showCharts['CVSS:2.0']) {
                cvss2P0SeverityRadarContainer.classList.remove('d-none');
            }
            if (showCharts['CVSS:3.0']) {
                cvss3P0SeverityRadarContainer.classList.remove('d-none');
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

            const nomenclature = selectedVector.getNomenclature();
            const headerSpanElement = cvss4MacroVectorExplanationCard.getElementsByClassName('card-header')[0].getElementsByTagName('span')[0];
            headerSpanElement.innerText = nomenclature + ' 4.0 MacroVector';

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
            const scores = calculatedVectorScores[vector.uniqueId];
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
            const scores = calculatedVectorScores[vector.uniqueId];
            const normalizedScores = calculatedNormalizedVectorScores[vector.uniqueId];
            const row = document.createElement('tr');
            tbody.appendChild(row);

            const nameElement = document.createElement('span');
            nameElement.innerText = vector.name;
            nameElement.classList.add('fw-bold');
            if (vector.cvssInstance instanceof CvssCalculator.Cvss2) {
                nameElement.classList.add('text-cvss-2');
            } else if (vector.cvssInstance instanceof CvssCalculator.Cvss3P0) {
                nameElement.classList.add('text-cvss-3P0');
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

            const cvssNameInputElements = selectedCvssDuplicatedSection.getElementsByClassName('cvss-vector-name');
            if (cvssNameInputElements.length > 0) {
                const cvssNameInputElement = cvssNameInputElements[0];
                cvssNameInputElement.value = selectedVectorContainerInstance.name;
                const cvssNameInputElementTargetWidth = CvssVectorRepresentation.findRealRenderedTextWidthWithFontOfElement(cvssNameInputElement, cvssNameInputElement.value);
                cvssNameInputElement.style.maxWidth = (cvssNameInputElementTargetWidth + 30) + 'px';
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

// by default, the base category user guides are only shown if the vector is empty upon selection
let forceUserGuidesVisible = false;

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

        // by default, show on non-base metrics or on all if the vector base metrics are empty
        const showUserGuides = forceUserGuidesVisible || componentCategory.name !== 'base' || !vectorInstance.isBaseFullyDefined();

        const queryMap = new Map();
        queryMap.set(componentCategory, componentsList);
        let shouldBeCollapsed = !expandedComponentCategories.includes(componentCategoryName);

        const vectorComponentString = selectedVector.toString(true, queryMap).replace(selectedVector.getVectorPrefix(), '');
        const accordionItem = document.createElement('div');

        accordionItem.classList.add('accordion-item');
        if (selectedVector.constructor === CvssCalculator.Cvss4P0) {
            accordionItem.classList.add('accordion-cvss-4P0');
        } else if (selectedVector.constructor === CvssCalculator.Cvss3P0) {
            accordionItem.classList.add('accordion-cvss-3P0');
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
        accordionBody.classList.add('accordion-body', 'position-relative');
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

                    // find all user guides in this componentsList
                    if (isFirst) {
                        if (showUserGuides) {
                            const userGuides = [];
                            for (let component of componentsList) {
                                const userGuide = findCvssUserGuide(vectorInstance.getVectorName(), component.shortName);
                                if (userGuide) {
                                    userGuides.push({
                                        userGuide: userGuide,
                                        component: component
                                    });
                                }
                            }

                            if (userGuides.length > 0) {
                                const userGuideButton = document.createElement('i');
                                userGuideButton.classList.add('position-absolute', 'bi', 'bi-question-circle-fill', 'text-secondary', 'user-guide-group');
                                userGuideButton.setAttribute('data-bs-toggle', 'popover');
                                userGuideButton.setAttribute('data-bs-placement', 'right');
                                userGuideButton.setAttribute('data-bs-content', 'Click to open a multiple-choice dialog to select the correct values for the metrics in this group.');
                                userGuideButton.setAttribute('title', 'User Guide: all ' + componentCategoryName + ' metrics');
                                userGuideButton.setAttribute('data-bs-trigger', 'hover');
                                accordionBody.appendChild(userGuideButton);

                                userGuideButton.addEventListener('click', () => {
                                    let index = 0;

                                    function openNextUserGuideModal() {
                                        if (index < userGuides.length) {
                                            openUserGuideModal(vectorInstance, userGuides[index].component, userGuides[index].userGuide, openNextUserGuideModal);
                                            index++;
                                        }
                                    }

                                    openNextUserGuideModal();
                                });
                            }
                        } else {
                            // add a dummy icon with a hint that user guides are available
                            const userGuideButton = document.createElement('i');
                            userGuideButton.classList.add('position-absolute', 'bi', 'bi-question-circle', 'text-danger', 'user-guide-group');
                            userGuideButton.setAttribute('data-bs-toggle', 'popover');
                            userGuideButton.setAttribute('data-bs-placement', 'right');
                            userGuideButton.setAttribute('data-bs-content', 'Base metrics that are already defined should not be modified during assessment. Instead, the temporal and environmental metric groups should be used to contextualize the provided vector. User guides are disabled for that reason, but can be forced by clicking this button.');
                            userGuideButton.setAttribute('title', 'User Guide disabled');
                            userGuideButton.setAttribute('data-bs-trigger', 'hover');
                            userGuideButton.setAttribute('data-bs-custom-class', 'popover-danger');
                            accordionBody.appendChild(userGuideButton);

                            // allow overriding the default behavior of showing user guides if the vector is empty using forceUserGuidesVisible
                            userGuideButton.addEventListener('click', () => {
                                forceUserGuidesVisible = !forceUserGuidesVisible;
                                setSelectedVector(selectedVector);
                            });
                        }
                    }
                }

                const componentContainer = document.createElement('div');
                componentContainer.classList.add('columns', 'cvss-component-selection-element-container', 'position-relative');
                accordionBody.appendChild(componentContainer);

                // user guide button if available
                const userGuide = findCvssUserGuide(vectorInstance.getVectorName(), component.shortName);
                if (userGuide && showUserGuides) {
                    const userGuideButton = document.createElement('i');
                    userGuideButton.classList.add('position-absolute', 'bi', 'bi-question-circle', 'text-secondary', 'user-guide-individual');
                    userGuideButton.setAttribute('data-bs-toggle', 'popover');
                    userGuideButton.setAttribute('data-bs-placement', 'right');
                    userGuideButton.setAttribute('data-bs-content', 'Click to open a multiple-choice dialog to select the correct value for this metric.');
                    userGuideButton.setAttribute('title', 'User Guide: ' + component.shortName);
                    userGuideButton.setAttribute('data-bs-trigger', 'hover');
                    componentContainer.appendChild(userGuideButton);

                    userGuideButton.addEventListener('click', () => {
                        openUserGuideModal(vectorInstance, component, userGuide);
                    });
                }

                // header
                const componentHeader = document.createElement('div');
                componentHeader.innerText = component.name;
                componentHeader.setAttribute('data-bs-toggle', 'popover');
                componentHeader.setAttribute('data-bs-placement', 'left');
                componentHeader.setAttribute('title', component.shortName + ' - ' + component.name);
                if (component.description) {
                    componentHeader.setAttribute('data-bs-html', true);
                    componentHeader.setAttribute('data-bs-content', component.description + '<br/>Click to copy metric value to clipboard.');
                } else {
                    componentHeader.setAttribute('data-bs-content', 'Click to copy metric value to clipboard.');
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
                        componentButton.classList.add('col-cvss-buttons-small');
                    } else {
                        componentButton.classList.add('col-cvss-buttons');
                    }

                    componentButton.type = 'button';

                    // componentValue.description as popover tooltip
                    componentButton.setAttribute('data-bs-toggle', 'popover');
                    componentButton.setAttribute('data-bs-placement', 'top');
                    componentButton.setAttribute('data-bs-content', componentValue.description);
                    componentButton.setAttribute('title', componentValue.shortName + ' - ' + componentValue.name);
                    componentButton.setAttribute('data-bs-trigger', 'hover focus');

                    if (componentValue.shortName === 'X' || componentValue.shortName === 'ND') {
                        componentButton.style.maxWidth = '33px';
                    }

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
                        let type;
                        if (componentValue.shortName === 'X' || componentValue.shortName === 'ND') {
                            if (componentCategoryName === 'base') {
                                type = 'danger';
                            } else {
                                type = 'outline-primary';
                            }
                        } else {
                            type = 'primary';
                        }
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
            expandedComponentCategories = [...new Set(expandedComponentCategories)];
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
        } else if (cvssInstance instanceof CvssCalculator.Cvss3P0) {
            vectorCssClass = 'bg-cvss-3P0';
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

function uploadJsonSchemaToAppendMultipleVectors() {
    const fileInput = document.createElement('input');
    fileInput.type = 'file';
    fileInput.accept = '.json';
    fileInput.onchange = function () {
        const file = fileInput.files[0];
        if (file) {
            const reader = new FileReader();
            reader.onload = function (e) {
                try {
                    const contents = e.target.result;
                    const json = JSON.parse(contents);
                    console.log(json);
                    document.getElementById('inputAddVectorByMultipleStrings').value = JSON.stringify(json, null, 2);
                    freeTextInputParseIntermediate();
                } catch (e) {
                    console.error(e);
                    createBootstrapToast('Failed to parse JSON', 'The uploaded file could not be parsed as JSON.', 'error');
                }
            };
            reader.readAsText(file);
        }
    };
    fileInput.click();
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
    if (element.hasAttribute('data-bs-toggle')) {
        const popover = bootstrap.Popover.getInstance(element);
        if (popover) {
            popover.update();
        }
        return;
    }
    const tooltipTriggerList = [].slice.call(element.querySelectorAll('[data-bs-toggle="popover"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Popover(tooltipTriggerEl);
    });
}

function unregisterAllTooltips(element) {
    // check if element already has data-bs-toggle="popover" attribute
    if (element.hasAttribute('data-bs-toggle')) {
        const popover = bootstrap.Popover.getInstance(element);
        if (popover) {
            popover.dispose();
        }
        return;
    }
    // find all that have already been initialized and destroy them
    const tooltipTriggerList = [].slice.call(element.querySelectorAll('[data-bs-toggle="popover"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        const popover = bootstrap.Popover.getInstance(tooltipTriggerEl);
        if (popover) {
            popover.dispose();
        }
    });
}

function createBootstrapToast(title, message, type = 'info', duration = 4000) {
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
        delay: duration
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
        /*for (let [name, shown, vector, version] of parsedVectorData) {
            if (vector.length === 0) {
                continue;
            }
            if (!name || name.length === 0) {
                name = undefined;
            }
            appendNewVector(vector, name, shown, version);
        }*/
        for (vectorData of parsedVectorData) {
            if (vectorData.length === 0) {
                continue;
            }

            let name = vectorData[0];
            const shown = vectorData[1];
            const vector = vectorData[2];
            const version = vectorData[3];
            let unmodifiedVector = vectorData.length >= 5 ? vectorData[4] : undefined;

            if (!name || name.length === 0) {
                name = undefined;
            }
            if (unmodifiedVector === null || unmodifiedVector === '' || unmodifiedVector === vector) {
                unmodifiedVector = undefined;
            }

            appendNewVector(vector, name, shown, version, unmodifiedVector);
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
            const vectorString = vector.cvssInstance.toString();
            const initialVectorString = vector.initialCvssInstance.toString();
            vectorData.push([vector.name, vector.shown, vectorString, vector.cvssInstance.getVectorName(), vectorString === initialVectorString ? undefined : initialVectorString]);
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

function downloadAllJsonSchema() {
    const allSchema = cvssVectors.map(vector => vector.createJsonSchema());
    const stringifySchema = JSON.stringify(allSchema);
    downloadText('cvss-vectors.json', stringifySchema);
}

function downloadText(filename, text) {
    filename = filename.toLowerCase()
        .replace(/[^a-z0-9._+]/g, '-')
        .replaceAll(/-+/g, '-')
        .replace(/^-/, '')
        .replaceAll(/-\./g, '\.');
    const element = document.createElement('a');
    element.setAttribute('href', 'data:text/plain;charset=utf-8,' + encodeURIComponent(text));
    element.setAttribute('download', filename);

    element.style.display = 'none';
    document.body.appendChild(element);

    element.click();

    document.body.removeChild(element);
}

// shift key actions
const shiftKeyStoredElements = new Map();

function shiftKeyChange(active) {
    const shiftActionElements = document.querySelectorAll('[data-cvss-shift-action]');

    for (let element of shiftActionElements) {
        if (active) {
            shiftKeyStoredElements.set(element, {
                content: element.innerHTML
            });

            const replacementIcon = element.getAttribute('data-cvss-shift-action-replacement-icon');
            const replacementText = element.getAttribute('data-cvss-shift-action-replacement-text');
            const retainWidth = element.getAttribute('data-cvss-shift-action-retain-width') === 'true';

            if (retainWidth) {
                const width = element.clientWidth;
                element.style.width = (width + 2) + 'px';
            }

            let replacementContent = '';
            if (replacementIcon && replacementText) {
                replacementContent = `<i class="bi bi-${replacementIcon}"></i> &nbsp;${replacementText}`;
            } else if (replacementIcon) {
                replacementContent = `<i class="bi bi-${replacementIcon}"></i>`;
            } else if (replacementText) {
                replacementContent = replacementText;
            }

            element.innerHTML = replacementContent;
        } else {
            const retainWidth = element.getAttribute('data-cvss-shift-action-retain-width') === 'true';

            if (retainWidth) {
                element.style.width = '';
            }

            const storedContent = shiftKeyStoredElements.get(element);
            if (storedContent) {
                element.innerHTML = storedContent.content;
            }
        }
    }
}

let shiftKeyDown = false;
document.addEventListener('keydown', (event) => {
    if (event.key === 'Shift' || event.key === 'Meta') {
        if (!shiftKeyDown && document.activeElement.tagName.toLowerCase() !== 'input') {
            shiftKeyDown = true;
            shiftKeyChange(true);
        }
    }
});

document.addEventListener('keyup', (event) => {
    if (event.key === 'Shift' || event.key === 'Meta') {
        if (shiftKeyDown) {
            shiftKeyDown = false;
            shiftKeyChange(false);
        }
    }
});

document.addEventListener('blur', () => {
    if (shiftKeyDown) {
        shiftKeyDown = false;
        shiftKeyChange(false);
    }
});

// check for option/alt key with up/down arrow key to select the next/previous vector
document.addEventListener('keydown', (event) => {
    if (event.key === 'ArrowUp' || event.key === 'ArrowDown') {
        if (event.altKey) {
            let currentIndex = -1;
            for (let i = 0; i < cvssVectors.length; i++) {
                if (cvssVectors[i].cvssInstance === selectedVector) {
                    currentIndex = i;
                    break;
                }
            }

            if (currentIndex === -1) {
                return;
            }

            let nextIndex = currentIndex;
            if (event.key === 'ArrowUp') {
                nextIndex--;
            } else if (event.key === 'ArrowDown') {
                nextIndex++;
            }

            if (nextIndex < 0) {
                nextIndex = cvssVectors.length - 1;
            } else if (nextIndex >= cvssVectors.length) {
                nextIndex = 0;
            }

            setSelectedVector(cvssVectors[nextIndex].cvssInstance);
        }
    }
});

// load page

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
    setTimeout(() => {
        additionalRadarChartContainer.classList.remove('d-none');
    }, 50);
} else {
    additionalRadarChartContainer.classList.remove('d-none');
}

function loadDemo() {
    const demoString = 'vector=[["CVSS%3A4.0"%2Ctrue%2C"CVSS%3A4.0%2FAV%3AP%2FAC%3AH%2FAT%3AN%2FPR%3AN%2FUI%3AN%2FVC%3AH%2FVI%3AL%2FVA%3AL%2FSC%3AH%2FSI%3AH%2FSA%3AH"%2C"CVSS%3A4.0"]%2C["3.1+2020-5934+(nist.gov)"%2Ctrue%2C"CVSS%3A3.1%2FAV%3AN%2FAC%3AL%2FPR%3AN%2FUI%3AN%2FS%3AC%2FC%3AL%2FI%3AL%2FA%3AN%2FE%3AP%2FRL%3AU%2FRC%3AC%2FMAV%3AN%2FMAC%3AL%2FMPR%3AN%2FMUI%3AN%2FMS%3AC%2FMC%3AL%2FMI%3AL%2FMA%3AL%2FCR%3AL%2FIR%3AM%2FAR%3AM"%2C"CVSS%3A3.1"]%2C["2.0+2020-5934+(nist.gov)"%2Ctrue%2C"AV%3AL%2FAC%3AH%2FAu%3AS%2FC%3AC%2FI%3AP%2FA%3AN%2FE%3AU%2FRL%3AU%2FRC%3AC%2FCDP%3ALM%2FTD%3AM%2FCR%3AH%2FIR%3AH%2FAR%3AH"%2C"CVSS%3A2.0"]]&open=temporal&selected=3.1+2020-5934+(nist.gov)';
    const baseUrl = window.location.href.split('?')[0];
    const decodedDemoString = decodeURIComponent(demoString);
    window.location.href = baseUrl + '?' + decodedDemoString;
}

setTimeout(() => {
    const currentHtmlVersion = document.getElementById('cvss-calculator-current-version').innerText;
    if (currentHtmlVersion !== '1.0.20') {
        createBootstrapToast('New version available', 'A new version of the CVSS Calculator is available. Please refresh the page to load the new version or clear the cache.', 'info', 10 * 1000);
    }
    const changelogBody = document.getElementById('cvss-calculator-changelog-body');
    const changelogHeader = changelogBody.getElementsByTagName('h5')[0];
    if (!changelogHeader.innerText.includes(currentHtmlVersion)) {
        createBootstrapToast('Version mismatch', 'The version of the CVSS Calculator does not match the version of the changelog. This is most likely a developer oversight.', 'warning', 10 * 1000);
    }
}, 100);
