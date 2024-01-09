import { VectorComponentValue } from "../CvssVector";

export interface ICvss4P0 {
    getComponentByString(component: string): VectorComponentValue;
}
